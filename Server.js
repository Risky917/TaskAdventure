const express = require('express');
const exphbs = require('express-handlebars');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, './public/uploads');
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + ext;
    cb(null, uniqueName);
  }
});

const upload = multer({ storage });

const { db, createUser, findUser, getTasks, getCharacterInfoByBaseImage } = require('./db/database');

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.render('Login', { error: 'You must first log in to view this page.' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.render('Login', { error: 'You must first log in to view this page.' });
  }

  const userId = req.session.user.id;

  db.get(`
    SELECT r.name FROM roles r
    INNER JOIN user_roles ur ON ur.roleId = r.id
    WHERE ur.userId = ?
  `, [userId], (err, row) => {
    if (err || !row || row.name !== 'admin') {
      return res.render('Login', { error: 'You do not have access to this page. you must be an admin.' });
    }
    next();
  });
}

const app = express();
const port = 3000;

app.engine('hbs', exphbs.engine({
  extname: 'hbs',
  defaultLayout: 'main',
  layoutsDir: path.join(__dirname, 'views/Layouts'),
  partialsDir: path.join(__dirname, 'views/Partials'),
  helpers: {
    eq: (a, b) => a == b,
    ifEquals: (a, b, options) => {
      if (a == b) {
        return options.fn(this);
      }
      return options.inverse(this);
    },
    lookupCharacter: (characters, id) => {
      return characters.find(character => character.id == id);
    },

    getCharacterImage: (character, characterInfo) => {
      if (!characterInfo) {
        console.warn('getCharacterImage: characterInfo is null or undefined', character);
        return '/img/default.png';
      }

      if (character.level >= 5 && characterInfo.evolutionStage2Image) {
        return characterInfo.evolutionStage2Image;
      } else if (character.level >= 2 && characterInfo.evolutionStage1Image) {
        return characterInfo.evolutionStage1Image;
      } else {
        return characterInfo.baseImage;
      }
    }
  }
}));
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'secretkey',
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    secure: false,
    maxAge: 3600000,
    sameSite: 'lax'
  }
}));

app.use((req, res, next) => {
  const user = req.session.user;

  if (!user) {
    res.locals.user = null;
    return next();
  }

  db.get(
    `SELECT 1 FROM user_roles ur
     JOIN roles r ON ur.roleId = r.id
     WHERE ur.userId = ? AND r.name = 'admin'`,
    [user.id],
    (err, row) => {
      if (err) {
        console.error('Admin role check failed:', err);
      }

      user.isAdmin = !!row;
      res.locals.user = user;
      next();
    }
  );
});

// Landing Page Route
app.get('/', (req, res) => {
  if (req.session && req.session.userId) {
    return res.redirect('/home');
  }

  res.render('LandingPage', { layout: 'landing' });
});


//Home
function calculateLevelAndXpProgress(totalXp) {
  let level = 1;
  let xpForNextLevel = 100;
  let remainingXp = totalXp;

  while (remainingXp >= xpForNextLevel) {
    remainingXp -= xpForNextLevel;
    level++;
    xpForNextLevel = 100 + (level - 1) * 50;
  }

  return {
    level,
    xpIntoCurrentLevel: remainingXp,
    xpToNextLevel: xpForNextLevel
  };
}

app.get('/home', requireLogin, (req, res) => {
  const userId = req.session.user.id;

  db.all(`
    SELECT c.*, ci.baseImage, ci.evolutionStage1Image, ci.evolutionStage2Image
    FROM characters c
    LEFT JOIN character_info ci ON c.characterInfoId = ci.id
    WHERE c.userId = ?
  `, [userId], (err, characters) => {
    if (err) {
      console.error("Error fetching characters with info:", err);
      return res.status(500).send('Error fetching characters');
    }

    if (!characters || characters.length === 0) {
      return res.render('Home', {
        user: req.session.user,
        characters: [],
        tasks: [],
        noCharacter: true,
        pageTitel: 'Home',
        selectedCharacter: null
      });
    }

    const characterId = parseInt(req.query.characterId) || characters[0].id;
    const selectedCharacter = characters.find(c => c.id === characterId);

    if (!selectedCharacter) {
      return res.status(404).send('Character not found');
    }

    db.all('SELECT * FROM tasks WHERE characterId = ? AND pending = 1', [characterId], (err, tasks) => {
      if (err) return res.status(500).send('Error fetching tasks');

      const totalXp = selectedCharacter.xp;
      const level = selectedCharacter.level;
      const { xpIntoCurrentLevel, xpToNextLevel } = calculateLevelAndXpProgress(totalXp);
      const xpPercentage = Math.min(100, (xpIntoCurrentLevel / xpToNextLevel) * 100);

      res.render('Home', {
        user: req.session.user,
        characters,
        tasks,
        noCharacter: false,
        selectedCharacterId: characterId,
        xp: totalXp,
        level,
        xpIntoCurrentLevel,
        xpToNextLevel,
        xpPercentage,
        selectedCharacter,
        pageTitel: 'Home'
      });
    });
  });
});

// XP gain route
app.post('/api/gain-xp', (req, res) => {
  const userId = req.session.user?.id;
  const characterId = parseInt(req.body.characterId);
  const xpGained = parseInt(req.body.xpGained);

  if (!userId || isNaN(characterId) || isNaN(xpGained)) {
    return res.status(400).json({ error: 'Invalid input' });
  }

  db.get(
    'SELECT xp, level FROM characters WHERE id = ? AND userId = ?',
    [characterId, userId],
    (err, character) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!character) return res.status(404).json({ error: 'Character not found' });

      const oldLevel = character.level;
      const totalXp = character.xp + xpGained;
      const { level: newLevel } = calculateLevelAndXpProgress(totalXp);

      db.run(
        'UPDATE characters SET xp = ?, level = ? WHERE id = ? AND userId = ?',
        [totalXp, newLevel, characterId, userId],
        function (updateErr) {
          if (updateErr) return res.status(500).json({ error: 'Failed to update XP' });

          res.json({ xp: totalXp, level: newLevel, leveledUp: newLevel > oldLevel });
        }
      );
    }
  );
});

// complete task
app.post('/task/complete/:id', requireLogin, (req, res) => {
  const taskId = req.params.id;
  const characterId = req.query.characterId;

  if (!characterId) return res.status(400).send('characterId is missing');

  db.get('SELECT * FROM tasks WHERE id = ?', [taskId], (err, task) => {
    if (err || !task) return res.status(500).send('Task not found');

    const taskXp = Number(task.xp) || 0;

    db.get('SELECT * FROM characters WHERE id = ?', [characterId], (err, character) => {
      if (err || !character) return res.status(500).send('Character not found');

      const userId = character.userId;
      const newXp = (character.xp || 0) + taskXp;
      let newLevel = calculateLevelAndXpProgress(newXp).level;

      db.run(
        'UPDATE characters SET xp = ?, level = ? WHERE id = ?',
        [newXp, newLevel, characterId],
        function (err) {
          if (err) return res.status(500).send('Update character failed');

          db.get('SELECT * FROM stats WHERE userId = ?', [userId], (err, stats) => {
            if (err || !stats) {
              console.warn('Stats niet gevonden voor userId:', userId);
              return res.redirect('/home?characterId=' + characterId);
            }

            const updatedTaskCompleted = (stats.taskCompleted || 0) + 1;
            const updatedXp = (stats.totalXpGained || 0) + taskXp;

            const updatedMostXp = Math.max(taskXp, stats.mostXpForOneTask || 0);

            db.run(
              'UPDATE stats SET taskCompleted = ?, totalXpGained = ?, mostXpForOneTask = ? WHERE userId = ?',
              [updatedTaskCompleted, updatedXp, updatedMostXp, userId],
              (err) => {
                if (err) console.error('error updating stats:', err);

                db.run('UPDATE tasks SET pending = 0, completed = 1 WHERE id = ?', [taskId],
                  function (err) {
                    if (err) return res.status(500).send('Task completion failed');

                    res.redirect('/home?characterId=' + characterId);

                  });
              }
            );
          });
        }
      );
    });
  });
});






//Stats route
app.get('/Stats', requireLogin, (req, res) => {
  const userId = req.session.user?.id;
  const username = req.session.user?.username;
  db.get('SELECT * FROM stats WHERE username = ?', [username], (err, stat) => {
    if (err) {
      console.error('Error fetching stats:', err);
      return res.status(500).send('Error fetching stats');
    }
    res.render('Stats', { stats: stat, pageTitel: 'Stats' });
  });
});


// Task Manager
app.get('/Taskmanager', requireLogin, (req, res) => {
  const userId = req.session.user.id;
  const today = new Date().toISOString().split('T')[0];
  const maxDate = '2050-12-31';
  db.run(`
    DELETE FROM tasks
    WHERE dueDate < date('now')
      AND characterId IN (SELECT id FROM characters WHERE userId = ?)
  `, [userId], (err) => {
    if (err) return res.status(500).send('Error deleting expired tasks');

    db.all(`
        SELECT c.*, ci.baseImage, ci.evolutionStage1Image, ci.evolutionStage2Image
        FROM characters c
        LEFT JOIN character_info ci ON c.characterInfoId = ci.id
        WHERE c.userId = ?
    `, [userId], (err, characters) => {
      if (err) return res.status(500).send('Error loading characters');
      if (characters.length === 0) return res.render('Taskmanager', { characters: [], tasks: [], pageTitel: 'Task Manager' });

      const characterIds = characters.map(c => c.id);
      const placeholders = characterIds.map(() => '?').join(',');

      db.all(
        `
        SELECT tasks.id, tasks.title, tasks.description, tasks.dueDate,
       tasks.completed, tasks.Pending AS Pending, tasks.xp,
       characters.name AS characterName
        FROM tasks
        JOIN characters ON tasks.characterId = characters.id
        WHERE tasks.characterId IN (${placeholders})
        AND tasks.completed == 0
        `,
        characterIds,
        (err, tasks) => {
          if (err) return res.status(500).send('Error loading tasks');
          res.render('Taskmanager', { characters, tasks, today, maxDate, pageTitel: 'Task Manager' });
        }
      );
    });
  });
});

// Handle task creation
app.post('/Taskmanager', requireLogin, (req, res) => {
  const { taskName, taskDeadline, taskDescription, characterId, taskXp } = req.body;

  db.run(
    `INSERT INTO tasks (title, description, dueDate, completed, pending, characterId, xp) VALUES (?, ?, ?, 0, 0, ?, ?)`,
    [taskName, taskDescription, taskDeadline, characterId, taskXp],
    err => {
      if (err) return res.status(500).send('Error adding task');
      res.redirect('/Taskmanager');
    }
  );
});

// Handle task accept
app.post('/task/accept/:id', requireLogin, (req, res) => {
  const taskId = req.params.id;
  const userId = req.session.user.id;

  db.run(`
    UPDATE tasks
    SET pending = 1
    WHERE id = ?
      AND characterId IN (
        SELECT id FROM characters WHERE userId = ?
      )
  `, [taskId, userId], err => {
    if (err) return res.status(500).json({ error: 'Error accepting task' });
    res.json({ success: true });
  });
});

app.post('/task/complete/:id', requireLogin, (req, res) => {
  const taskId = req.params.id;

  db.run(
    `UPDATE tasks SET completed = 1, pending  = 0 WHERE id = ?`,
    [taskId],
    function (err) {
      if (err) return res.status(500).send('Error completing task');
      res.redirect('/home');
    }
  );
});

// Handle task delete
app.post('/task/delete/:id', requireLogin, (req, res) => {
  const taskId = req.params.id;
  const userId = req.session.user.id;

  db.run(`
    DELETE FROM tasks
    WHERE id = ?
      AND characterId IN (
        SELECT id FROM characters WHERE userId = ?
      )
  `, [taskId, userId], err => {
    if (err) return res.status(500).send('Error deleting task');
    res.redirect('/Taskmanager');
  });
});


// Login
app.get('/Login', (req, res) => res.render('Login', { pageTitel: 'Login' }));

app.post('/Login', (req, res) => {
  const { username, password } = req.body;
  findUser(username, (err, user) => {
    if (err || !user) return res.render('Login', { error: 'User not found.', pageTitel: 'Login' });
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) return res.render('Login', { error: 'Password incorrect.' });
      req.session.user = user;
      res.redirect('/home');
    });
  });
});

// Create Account
app.get('/CreateAccount', (req, res) => res.render('CreateAccount', { pageTitel: 'Create Account' }));

app.post('/CreateAccount', upload.single('profileImage'), (req, res) => {
  const { email, username, password, confirmPassword } = req.body;
  const profileImage = req.file ? `/uploads/${req.file.filename}` : null;

  if (password !== confirmPassword) {
    return res.render('CreateAccount', { error: 'Passwords do not match.' });
  }

  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{6,}$/;
  if (!passwordRegex.test(password)) {
    return res.render('CreateAccount', {
      error: 'Password must be at least 6 characters long and include one uppercase letter, one lowercase letter, and one special character.',
    });
  }

  db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], (err, existingUser) => {
    if (err) {
      return res.render('CreateAccount', { error: 'An error has occurred. Please try again.' });
    }

    if (existingUser) {
      return res.render('CreateAccount', { error: 'Username or e-mail already exists.' });
    }

    createUser(email, username, password, profileImage, (err, userId) => {
      if (err) {
        return res.render('CreateAccount', { error: 'An error occurred while trying to create your account.' });
      }

      db.get('SELECT id FROM roles WHERE name = ?', ['user'], (err, roleRow) => {
        if (err || !roleRow) {
          req.session.user = { id: userId, username, email, profileImage };
          return res.redirect('/CharacterCreation');
        }

        const roleId = roleRow.id;

        db.run('INSERT INTO user_roles (userId, roleId) VALUES (?, ?)', [userId, roleId], (err) => {
          if (err) {
            console.error('Failed to assign role:', err);
          }

          db.run('INSERT INTO stats (userId, username) VALUES (?, ?)', [userId, username], (err) => {
            if (err) {
              console.error("❌ could not create stats for new user:", err);
            }

            req.session.user = { id: userId, username, email, profileImage };
            res.redirect('/CharacterCreation');
          });
        });
      });
    });
  });
});

// Logout
app.post('/Logout', (req, res) => {
  req.session.destroy(() => res.redirect('/home'));
});

// Admin Panel Route
app.get('/AdminPanel', requireAdmin, (req, res) => {
  db.all(`
    SELECT 
      u.id AS userId, u.username, u.email,
      c.id AS characterId, c.name AS characterName, c.xp AS characterXP,
      t.id AS taskId, t.title AS taskTitle, t.description AS taskDescription,
      t.xp AS taskXP, t.dueDate AS taskDueDate,
      t.pending, t.characterId AS taskCharacterId
    FROM users u
    LEFT JOIN characters c ON c.userId = u.id
    LEFT JOIN tasks t ON t.characterId = c.id AND t.pending = 1
    ORDER BY u.id
  `, [], (err, rows) => {
    if (err) return res.status(500).send('Failed to load admin panel');

    const usersMap = {};
    rows.forEach(row => {
      if (!usersMap[row.userId]) {
        usersMap[row.userId] = {
          id: row.userId,
          username: row.username,
          email: row.email,
          characters: [],
          tasks: []
        };
      }

      if (row.characterId && !usersMap[row.userId].characters.find(c => c.id === row.characterId)) {
        usersMap[row.userId].characters.push({
          id: row.characterId,
          name: row.characterName,
          xp: row.characterXP
        });
      }

      if (row.taskId && !usersMap[row.userId].tasks.find(t => t.id === row.taskId)) {
        usersMap[row.userId].tasks.push({
          id: row.taskId,
          title: row.taskTitle,
          description: row.taskDescription,
          xp: row.taskXP,
          dueDate: row.taskDueDate,
          characterName: row.characterName
        });
      }
    });

    res.render('AdminPanel', { users: Object.values(usersMap), pageTitel: 'Admin Panel' });
  });
});


// Change Username
app.post('/admin/change-username', requireAdmin, (req, res) => {
  const { userId, newUsername } = req.body;
  db.run(`UPDATE users SET username = ? WHERE id = ?`, [newUsername, userId], err => {
    if (err) return res.status(500).send('Error updating username');
    res.redirect('/AdminPanel');
  });
});

// Delete User
app.post('/admin/delete-user', requireAdmin, (req, res) => {
  const { userId } = req.body;
  db.run(`DELETE FROM users WHERE id = ?`, [userId], err => {
    if (err) return res.status(500).send('Error deleting user');
    res.redirect('/AdminPanel');
  });
});

// Delete Character
app.post('/admin/delete-character', requireAdmin, (req, res) => {
  const { characterId } = req.body;
  db.run(`DELETE FROM characters WHERE id = ?`, [characterId], err => {
    if (err) return res.status(500).send('Error deleting character');
    res.redirect('/AdminPanel');
  });
});

// Finish Task (mark as completed)
app.post('/admin/finish-task', requireAdmin, (req, res) => {
  const { taskId } = req.body;
  db.run(`UPDATE tasks SET pending = 0, completed = 1 WHERE id = ?`, [taskId], err => {
    if (err) return res.status(500).send('Error finishing task');
    res.redirect('/AdminPanel');
  });
});

// Delete Task
app.post('/admin/delete-task', requireAdmin, (req, res) => {
  const { taskId } = req.body;
  db.run(`DELETE FROM tasks WHERE id = ?`, [taskId], err => {
    if (err) return res.status(500).send('Error deleting task');
    res.redirect('/AdminPanel');
  });
});

// update character XP
app.post('/admin/update-character-xp', (req, res) => {
  const characterId = parseInt(req.body.characterId);
  const newTotalXp = parseInt(req.body.newXp);

  if (isNaN(characterId) || isNaN(newTotalXp)) {
    return res.status(400).send('Invalid input');
  }

  const xpThreshold = 100;
  const newLevel = Math.floor(newTotalXp / xpThreshold) + 1;

  db.run(
    'UPDATE characters SET xp = ?, level = ? WHERE id = ?',
    [newTotalXp, newLevel, characterId],
    function (err) {
      if (err) {
        console.error("DB UPDATE error:", err);
        return res.status(500).send('Failed to update XP and level');
      }

      console.log(`Character ${characterId} updated to XP: ${newTotalXp}, Level: ${newLevel}`);
      res.redirect('/adminpanel');
    }
  );
});

// Focus Mode route
app.get('/FocusMode', requireLogin, (req, res) => {
  res.render('FocusMode', { pageTitel: 'Focus Mode' });
});

// Helper functies
function getCharacters(userId, callback) {
  db.all(`
    SELECT c.id, c.name, c.level,
           ci.baseImage, ci.evolutionStage1Image, ci.evolutionStage2Image
    FROM characters c
    LEFT JOIN character_info ci ON c.characterInfoId = ci.id
    WHERE c.userId = ?
  `, [userId], (err, characters) => {
    if (err) return callback(err);
    callback(null, characters);
  });
}

function renderSettingsPage(res, user, alert) {
  getCharacters(user.id, (err, characters) => {
    if (err) {
      return res.render('Settings', {
        user,
        characters: [],
        alert: { type: 'error', message: 'Error loading characters' }
      });
    }

    res.render('Settings', {
      user,
      characters,
      alert,
      pageTitel: 'Settings'
    });
  });
}

// get Settings pagina
app.get('/Settings', requireLogin, (req, res) => {
  const user = req.session.user;
  const alert = req.session.alert;
  delete req.session.alert;

  renderSettingsPage(res, user, alert);
});

// Change Password
app.post('/Settings/changePassword', requireLogin, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = req.session.user;

  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{6,}$/;

  if (!passwordRegex.test(newPassword)) {
    req.session.alert = {
      type: 'error',
      message: 'Password must be at least 6 characters long and include one uppercase letter, one lowercase letter, and one special character.'
    };
    return res.redirect('/Settings');
  }

  findUser(user.username, (err, dbUser) => {
    if (err || !dbUser) {
      req.session.alert = { type: 'error', message: 'User not found' };
      return res.redirect('/Settings');
    }

    bcrypt.compare(currentPassword, dbUser.password, (err, isMatch) => {
      if (err || !isMatch) {
        req.session.alert = { type: 'error', message: 'Incorrect current password' };
        return res.redirect('/Settings');
      }

      bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
        if (err) {
          req.session.alert = { type: 'error', message: 'Error hashing new password' };
          return res.redirect('/Settings');
        }

        db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id], (err) => {
          if (err) {
            req.session.alert = { type: 'error', message: 'Error updating password' };
            return res.redirect('/Settings');
          }

          req.session.alert = { type: 'success', message: 'Password updated successfully' };
          res.redirect('/Settings');
        });
      });
    });
  });
});

// Delete Account
app.post('/Settings/removeAccount', requireLogin, (req, res) => {
  const user = req.session.user;

  db.run(`
    DELETE FROM tasks 
    WHERE characterId IN (
      SELECT id FROM characters WHERE userId = ?
    )
  `, [user.id], (err) => {
    if (err) {
      req.session.alert = { type: 'error', message: 'Error deleting tasks' };
      return res.redirect('/Settings');
    }

    db.run('DELETE FROM characters WHERE userId = ?', [user.id], (err) => {
      if (err) {
        req.session.alert = { type: 'error', message: 'Error deleting characters' };
        return res.redirect('/Settings');
      }

      db.run('DELETE FROM user_roles WHERE userId = ?', [user.id], (err) => {
        if (err) {
          req.session.alert = { type: 'error', message: 'Error deleting user roles' };
          return res.redirect('/Settings');
        }

        db.run('DELETE FROM stats WHERE userId = ?', [user.id], (err) => {
          if (err) {
            req.session.alert = { type: 'error', message: 'Error deleting stats' };
            return res.redirect('/Settings');
          }

          db.run('DELETE FROM users WHERE id = ?', [user.id], (err) => {
            if (err) {
              req.session.alert = { type: 'error', message: 'Error deleting account' };
              return res.redirect('/Settings');
            }

            req.session.destroy(() => {
              res.redirect('/Login');
            });
          });
        });
      });
    });
  });
});

// Delete Character
app.post('/Settings/removecharacter', requireLogin, (req, res) => {
  const user = req.session.user;
  const characterId = req.body.characterId;

  db.get('SELECT COUNT(*) AS count FROM characters WHERE userId = ?', [user.id], (err, row) => {
    if (err) {
      req.session.alert = { type: 'error', message: 'Error checking characters' };
      return res.redirect('/Settings');
    }

    if (row.count <= 1) {
      req.session.alert = { type: 'error', message: 'You must keep at least one character.' };
      return res.redirect('/Settings');
    }


    db.get('SELECT * FROM characters WHERE id = ? AND userId = ?', [characterId, user.id], (err, character) => {
      if (err || !character) {
        req.session.alert = { type: 'error', message: 'Character not found or not yours' };
        return res.redirect('/Settings');
      }

      db.run('DELETE FROM tasks WHERE characterId = ?', [characterId], (err) => {
        if (err) {
          req.session.alert = { type: 'error', message: 'Error deleting tasks' };
          return res.redirect('/Settings');
        }

        db.run('DELETE FROM characters WHERE id = ?', [characterId], (err) => {
          if (err) {
            req.session.alert = { type: 'error', message: 'Error deleting character' };
            return res.redirect('/Settings');
          }

          req.session.alert = { type: 'success', message: 'Character removed successfully' };
          res.redirect('/Settings');
        });
      });
    });
  });
});


// Access Rights and Permissions link
app.get('/access-rights', (req, res) => {
  res.redirect('https://en.wikipedia.org/wiki/Access_control');
});

// Leaderboard
app.get('/leaderboard', requireLogin, (req, res) => {
  const userId = req.session.user?.id;
  console.log("Leaderboard accessed by user ID:", userId);

  if (!userId) {
    return res.status(401).send("Not logged in");
  }

  // Step 1: Check if the user is in a class
  db.get(`SELECT classId FROM class_users WHERE userId = ?`, [userId], (err, classRow) => {
    if (err) {
      console.error("Error getting classId:", err.message);
      return res.status(500).send("Database error");
    }

    const isInClass = !!classRow;
    const classId = classRow?.classId;

    // Step 2: Get global top 10
    db.all(`
      SELECT c.name, c.xp, c.level, ci.baseImage, ci.evolutionStage1Image, ci.evolutionStage2Image
      FROM characters c
      LEFT JOIN character_info ci ON c.characterInfoId = ci.id
      ORDER BY c.xp DESC
      LIMIT 10
    `, [], (err, globalRows) => {
      if (err) {
        console.error("Error fetching global leaderboard:", err.message);
        return res.status(500).send("Database error");
      }

      const top3 = globalRows.slice(0, 3);
      const others = globalRows.slice(3);

      if (!isInClass) {
        // User not in a class – only show global leaderboard
        return res.render('LeaderBoard', {
          top3,
          others,
          classTop3: [],
          classOthers: [],
          pageTitel: 'Leaderboard',
          noClass: true
        });
      }

      // Step 3: Get class leaderboard
      db.all(`
        SELECT c.name, c.xp, c.level, ci.baseImage, ci.evolutionStage1Image, ci.evolutionStage2Image
        FROM characters c
        JOIN class_users cu ON cu.userId = c.userId
        LEFT JOIN character_info ci ON c.characterInfoId = ci.id
        WHERE cu.classId = ?
        ORDER BY c.xp DESC
        LIMIT 10
      `, [classId], (err, classRows) => {
        if (err) {
          console.error("Error fetching class leaderboard:", err.message);
          return res.status(500).send("Database error");
        }

        const classTop3 = classRows.slice(0, 3);
        const classOthers = classRows.slice(3);

        res.render('LeaderBoard', {
          top3,
          others,
          classTop3,
          classOthers,
          pageTitel: 'Leaderboard',
          noClass: false
        });
      });
    });
  });
});







app.post('/admin/delete-user', requireAdmin, (req, res) => {
  const { userId } = req.body;
  db.run(`DELETE FROM users WHERE id = ?`, [userId], err => {
    if (err) return res.status(500).send('Error deleting user');
    res.redirect('/AdminPanel');
  });
});

// Character Creation GET route
app.get('/CharacterCreation', requireLogin, (req, res) => res.render('CharacterCreation', { pageTitel: 'Character Creation' }));

// Character Creation POST
app.post('/CharacterCreation', (req, res) => {
  const { name, gender, imagevalue } = req.body;
  const userId = req.session.user?.id;

  if (!userId) {
    return res.status(401).send("Unauthorized: You must be logged in.");
  }

  getCharacterInfoByBaseImage(imagevalue, (err, characterInfo) => {
    if (err || !characterInfo) {
      console.error('Error fetching character info:', err);
      return res.status(500).json({ success: false, message: 'Selected character image info not found.' });
    }

    const characterInfoId = characterInfo.id;

    db.run(
      'INSERT INTO characters (userId, name, gender, characterInfoId) VALUES (?, ?, ?, ?)', // Use characterInfoId
      [userId, name, gender, characterInfoId],
      function (err) {
        if (err) {
          console.error('Error during DB insert for character:', err.message);
          return res.status(500).json({ success: false, message: 'Error adding character to the database' });
        }

        return res.json({ success: true, message: 'Character created successfully!' });
      }
    );
  });
});

// GET profile
app.get('/profile', requireLogin, (req, res) => {
  const user = req.session.user;

  db.get(`SELECT username, email FROM users WHERE id = ?`, [user.id], (err, row) => {
    if (err) {
      return res.status(500).send('Error retrieving profile.');
    }

    res.render('Profile', { user: row, });
  });
});

// Update profile
app.post('/profile/update', requireLogin, (req, res) => {
  const { username, email } = req.body;
  const userId = req.session.user.id;

  if (!username || !email) {
    return res.status(400).json({ success: false, message: 'All fields are required!' });
  }

  const checkSql = `SELECT id FROM users WHERE username = ? AND id != ?`;
  db.get(checkSql, [username, userId], (err, row) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'DatabaseError.' });
    }

    if (row) {
      return res.status(400).json({ success: false, message: 'Username already in use.' });
    }

    const getOldUsernameSql = `SELECT username FROM users WHERE id = ?`;
    db.get(getOldUsernameSql, [userId], (err, user) => {
      if (err || !user) {
        return res.status(500).json({ success: false, message: 'User not found.' });
      }

      const oldUsername = user.username;

      const updateUserSql = `UPDATE users SET username = ?, email = ? WHERE id = ?`;
      db.run(updateUserSql, [username, email, userId], function (err) {
        if (err) {
          return res.status(500).json({ success: false, message: 'User update error.' });
        }

        const updateStatsSql = `UPDATE stats SET username = ? WHERE username = ?`;
        db.run(updateStatsSql, [username, oldUsername], function (err) {
          if (err) {
            return res.status(500).json({ success: false, message: 'Error during stats update.' });
          }

          req.session.user.username = username;
          req.session.user.email = email;

          return res.json({ success: true, message: 'Profile updated successfully.' });
        });
      });
    });
  });
});

// Reset password
app.get('/reset-password', (req, res) => {
  res.render('reset-password');
});
app.post('/reset-password', (req, res) => {
  const { username, newPassword } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.render('reset-password', { error: 'DatabaseError' });
    if (!user) return res.render('reset-password', { error: 'User not found' });

    const hashed = bcrypt.hashSync(newPassword, 10);

    db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, user.id], (err2) => {
      if (err2) {
        return res.render('reset-password', { error: 'Could not update password' });
      }
      res.render('reset-password', { success: 'Password changed successfully' });
      res.redirect('/Login?reset=success');
    });
  });
});

// Classroom
app.get('/Classroom', requireLogin, async (req, res) => {
  const user = req.session.user;

  if (!user || !user.id) {
    return res.status(401).send("User not logged in");
  }

  const userId = user.id;

  try {
    const classesQuery = `
            SELECT
                c.id,
                c.name AS className,
                c.code,
                c.characterId,
                c.user_id,
                tu.username AS teacherUsername
            FROM classes c
            JOIN class_users cu ON c.id = cu.classId
            JOIN users tu ON c.user_id = tu.id
            WHERE cu.userId = ?
        `;

    let classes = await new Promise((resolve, reject) => {
      db.all(classesQuery, [userId], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });

    if (classes.length === 0) {
      const charQuery = `SELECT id, name FROM characters WHERE userId = ?`;
      let characters = await new Promise((resolve, reject) => {
        db.all(charQuery, [userId], (err, rows) => {
          if (err) reject(err);
          resolve(rows);
        });
      });
      return res.render('CreateClassroom', {
        pageTitel: 'Create New Class',
        message: 'You are not yet in a class. Create one!',
        characters
      });
    }

    const classesWithMembers = await Promise.all(classes.map(async (classroom) => {
      const membersQuery = `
                SELECT
                    u.username,
                    ch.name AS characterName,
                    ch.level,
                    ch.xp
                FROM class_users clu
                JOIN users u ON clu.userId = u.id
                LEFT JOIN characters ch ON u.id = ch.userId
                WHERE clu.classId = ?
                AND u.id != ?
                GROUP BY u.id
                ORDER BY ch.xp DESC, ch.id ASC
            `;

      const members = await new Promise((resolve, reject) => {
        db.all(membersQuery, [classroom.id, classroom.user_id], (err, memberRows) => {
          if (err) {
            console.error(`❌ Error fetching members for class ${classroom.id}:`, err.message);
            return reject(err);
          }
          if (!memberRows) {
            console.warn(`⚠️ No member data returned for class ${classroom.id}.`);
            return resolve([]);
          }
          resolve(memberRows.map(member => ({
            username: member.username,
            character: member.characterName || 'No character',
            level: member.level || 0,
            xp: member.xp || 0
          })));
        });
      });

      const isTeacher = (classroom.user_id === userId);

      return {
        ...classroom,
        members: members,
        isTeacher: isTeacher
      };
    }));

    console.log("DEBUG: Final classes data with members:", JSON.stringify(classesWithMembers, null, 2));

    res.render('Classroom', { classes: classesWithMembers, pageTitel: 'My Class' });

  } catch (err) {
    console.error("❌ Error fetching classes and members:", err.message);
    return res.status(500).send("Internal server error fetching class data.");
  }
});

// Create classroom
app.get('/CreateClassroom', requireLogin, (req, res) => {
  const user = req.session.user;
  const userId = user.id;

  const charQuery = `SELECT id, name FROM characters WHERE userId = ?`;

  db.all(charQuery, [userId], (err, characters) => {
    if (err) {
      console.error("❌ Error fetching characters:", err);
      return res.status(500).send("Error fetching characters.");
    }

    res.render('CreateClassroom', {
      pageTitel: 'Create New Class',
      message: null,
      characters
    });
  });
});
app.post('/CreateClassroom', requireLogin, (req, res) => {
  const { className, characterId, code } = req.body;
  console.log("DEBUG: characterId from req.body:", characterId);
  console.log("DEBUG: className from req.body:", className);
  console.log("DEBUG: code from req.body:", code);
  const userId = req.session.user.id;

  if (!userId) {
    console.error("❌ userId is missing in session for /CreateClassroom POST");
    return res.redirect('/login');
  }

  if (!className || !characterId || !code) {
    console.error("❌ Missing required fields for classroom creation.");
    return res.status(400).send("All fields are required.");
  }

  db.get('SELECT id FROM characters WHERE id = ? AND userId = ?', [characterId, userId], (err, charRow) => {
    if (err || !charRow) {
      console.error("❌ Selected character does not belong to the user or does not exist:", err);
      return res.status(403).send("You can only choose a character that belongs to you.");
    }

    db.get('SELECT id FROM classes WHERE name = ?', [className], (err, existingClassByName) => {
      if (err) {
        console.error("❌ Error checking unique class name:", err.message);
        return res.status(500).send("Internal server error checking class name.");
      }
      if (existingClassByName) {
        console.error("❌ Class with this name already exists:", className);
        const charQuery = `SELECT id, name FROM characters WHERE userId = ?`;
        db.all(charQuery, [userId], (err, characters) => {
          if (err) {
            console.error("❌ Error fetching characters after name error:", err);
            return res.status(500).send("Error fetching characters.");
          }
          return res.render('CreateClassroom', {
            pageTitel: 'Create New Class',
            message: 'This class name is already in use. Choose another one.',
            characters,
            oldClassName: className,
            oldCharacterId: characterId,
            oldCode: code
          });
        });
        return;
      }

      const insertClassQuery = `
                INSERT INTO classes (name, user_id, characterId, code)
                VALUES (?, ?, ?, ?)
            `;

      db.run(insertClassQuery, [className, userId, characterId, code], function (err) {
        if (err) {
          console.error("❌ Error adding class:", err.message);
          return res.status(500).send("Internal server error creating class.");
        }

        const classId = this.lastID;

        db.run('INSERT INTO class_users (classId, userId) VALUES (?, ?)', [classId, userId], (err) => {
          if (err) {
            console.error("❌ Error adding user to class_users:", err.message);
            return res.status(500).send("Error adding user to class.");
          }
          console.log("✅ New class added with ID:", classId, "and user added to class.");
          res.redirect('/Classroom');
        });
      });
    });
  });
});

// Delete classroom
app.post('/Classroom/:id/delete', requireLogin, (req, res) => {
  const classId = req.params.id;
  const userId = req.session.user.id;

  if (!userId) {
    console.error("❌ userId is missing in session for /Classroom/:id/delete POST");
    return res.status(401).send("User not logged in.");
  }

  if (!classId) {
    console.error("❌ Class ID is missing for delete request.");
    return res.status(400).send("Invalid class ID.");
  }

  db.get('SELECT user_id FROM classes WHERE id = ?', [classId], (err, classRow) => {
    if (err) {
      console.error(`❌ Error checking class creator for class ${classId}:`, err.message);
      return res.status(500).send("Internal server error.");
    }
    if (!classRow) {
      console.warn(`⚠️ Class with ID ${classId} not found for deletion.`);
      return res.status(404).send("Class not found.");
    }
    if (classRow.user_id !== userId) {
      console.warn(`⚠️ User ${userId} tried to delete class ${classId} without being the owner.`);
      return res.status(403).send("You do not have permission to delete this class.");
    }

    db.run('DELETE FROM class_users WHERE classId = ?', [classId], (err) => {
      if (err) {
        console.error(`❌ Error deleting members from class ${classId}:`, err.message);
        return res.status(500).send("Error deleting class members.");
      }

      db.run('DELETE FROM classes WHERE id = ?', [classId], function (err) {
        if (err) {
          console.error(`❌ Error deleting class ${classId}:`, err.message);
          return res.status(500).send("Error deleting the class.");
        }

        if (this.changes === 0) {
          console.warn(`⚠️ Class with ID ${classId} was already deleted.`);
        } else {
          console.log(`✅ Class with ID ${classId} successfully deleted.`);
        }
        res.redirect('/Classroom');
      });
    });
  });
});

// Leave classroom
app.post('/Classroom/:id/leave', requireLogin, (req, res) => {
  const classId = req.params.id;
  const userId = req.session.user.id;

  if (!userId) {
    console.error("❌ userId is missing in session for /Classroom/:id/leave POST");
    return res.status(401).send("User not logged in.");
  }

  if (!classId) {
    console.error("❌ Class ID is missing for leave request.");
    return res.status(400).send("Invalid class ID.");
  }

  const deleteQuery = `DELETE FROM class_users WHERE classId = ? AND userId = ?`;

  db.run(deleteQuery, [classId, userId], function (err) {
    if (err) {
      console.error(`❌ Error leaving class ${classId} by user ${userId}:`, err.message);
      return res.status(500).send("Error leaving the class.");
    }

    if (this.changes === 0) {
      console.warn(`⚠️ User ${userId} was not a member of class ${classId} or has already left.`);
    } else {
      console.log(`✅ User ${userId} left class ${classId}.`);
    }
    res.redirect('/Classroom');
  });
});

// Join classroom
app.get('/joinClassroom', requireLogin, (req, res) => {
  const message = req.session.joinClassMessage;
  delete req.session.joinClassMessage;

  res.render('JoinClassroom', {
    pageTitel: 'Join Classroom',
    message: message || null
  });
});

app.post('/joinClassroom', requireLogin, (req, res) => {
  const userId = req.session.user.id;
  const { name, code } = req.body;

  if (!name || !code) {
    req.session.joinClassMessage = 'Please enter both the class name and code.';
    return res.redirect('/joinClassroom');
  }

  const query = `SELECT * FROM classes WHERE name = ? AND code = ?`;

  db.get(query, [name, code], (err, classroom) => {
    if (err) {
      console.error("❌ Error searching classroom:", err);
      req.session.joinClassMessage = 'An internal error occurred. Please try again.';
      return res.redirect('/joinClassroom');
    }

    if (!classroom) {
      req.session.joinClassMessage = 'No class found with this name and code.';
      return res.redirect('/joinClassroom');
    }

    const checkUserInClass = `SELECT * FROM class_users WHERE classId = ? AND userId = ?`;

    db.get(checkUserInClass, [classroom.id, userId], (err, row) => {
      if (err) {
        console.error("❌ Error checking class membership:", err);
        req.session.joinClassMessage = 'An internal error occurred while checking your membership.';
        return res.redirect('/joinClassroom');
      }

      if (row) {
        req.session.joinClassMessage = 'You are already a member of this class.';
        return res.redirect('/Classroom');
      }

      const insertUser = `INSERT INTO class_users (classId, userId) VALUES (?, ?)`;

      db.run(insertUser, [classroom.id, userId], (err) => {
        if (err) {
          console.error("❌ Error adding to class:", err);
          req.session.joinClassMessage = 'An error occurred while adding to the class.';
          return res.redirect('/joinClassroom');
        }

        req.session.joinClassMessage = 'You have successfully joined the class!';
        res.redirect('/Classroom');
      });
    });
  });
});

//Friends
app.get('/Friends', requireLogin, (req, res) => {
    db.all(`
        SELECT *
        FROM users
        ORDER BY users.username ASC;
    `, [], (err, rows) => {
        if (err) {
            console.error("Query error:", err.message);
            return res.status(500).send("Database error");
        }

        const potentialFriends = rows.slice(0);

        res.render('Friends', { potentialFriends, pageTitle: 'Users' });
    });
});

// Add Friend Route
app.post('/addFriend', requireLogin, (req, res) => {
    const currentUserId = req.session.user.id;
    const potentialFriendId = req.body.friendId;
    console.log("DEBUG: currentUserId:", currentUserId);
    console.log("DEBUG: potentialFriendId:", potentialFriendId);
    console.log("DEBUG: Type of potentialFriendId:", typeof potentialFriendId);

    if (!potentialFriendId) {
        return res.status(400).json({ success: false, message: 'Friend ID is missing.' });
    }
    if (currentUserId === parseInt(potentialFriendId)) {
        return res.status(400).json({ success: false, message: 'You cannot add yourself as a friend.' });
    }

    db.get(`
        SELECT * FROM friends
        WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
    `, [currentUserId, potentialFriendId, potentialFriendId, currentUserId], (err, existingFriendship) => {
        if (err) {
            console.error("Database error checking existing friendship:", err.message);
            return res.status(500).json({ success: false, message: "Database error." });
        }

        if (existingFriendship) {
            let message = '';
            if (existingFriendship.status === 'pending') {
                if (existingFriendship.user1_id === currentUserId) {
                    message = 'Friend request already sent.';
                } else {
                    message = 'You have a pending friend request from this user. Accept it on your Friends page!';
                }
            } else if (existingFriendship.status === 'accepted') {
                message = 'You are already friends with this user.';
            }
            return res.status(409).json({ success: false, message: message });
        }

        db.run(`
            INSERT INTO friends (user1_id, user2_id, status)
            VALUES (?, ?, 'pending')
        `, [currentUserId, potentialFriendId], function (err) {
            if (err) {
                console.error("Database error adding friend:", err.message);
                return res.status(500).json({ success: false, message: "Could not send friend request." });
            }
            console.log(`Friend request sent: User ${currentUserId} to User ${potentialFriendId}`);
            res.status(200).json({ success: true, message: "Friend request sent!" });
        });
    });
});


// Friends Requests Page
app.get('/friend-requests', requireLogin, (req, res) => {
    const currentUserId = req.session.user.id;

    if (!currentUserId) {
        return res.redirect('/login');
    }

    db.all(`
        SELECT
            f.id AS requestId,
            u.id AS userId,
            u.username,
            u.email
        FROM
            friends f
        JOIN
            users u ON f.user1_id = u.id
        WHERE
            f.user2_id = ?
            AND f.status = 'pending';
    `, [currentUserId], (err, pendingRequests) => {
        if (err) {
            console.error("Query error fetching friend requests:", err.message);
            return res.status(500).send("Database error fetching requests");
        }

        res.render('friendRequests', {
            pendingRequests,
            pageTitle: 'Friend Requests'
        });
    });
});


// Handle Friend Request
app.post('/handle-friend-request', requireLogin, (req, res) => {
    const currentUserId = req.session.user.id; 
    const { requestId, action } = req.body;

    if (!requestId || !action || (action !== 'accept' && action !== 'decline')) {
        return res.status(400).json({ success: false, message: 'Invalid request.' });
    }

    const newStatus = (action === 'accept') ? 'accepted' : 'declined';

    db.run(`
        UPDATE friends
        SET status = ?
        WHERE id = ? AND user2_id = ? AND status = 'pending';
    `, [newStatus, requestId, currentUserId], function (err) {
        if (err) {
            console.error("Database error updating friend request status:", err.message);
            return res.status(500).json({ success: false, message: "Could not process request." });
        }

        if (this.changes === 0) {
            console.warn(`Attempted to update request ${requestId} but no rows changed. User: ${currentUserId}, Action: ${action}`);
            return res.status(404).json({ success: false, message: "Request not found or not authorized." });
        }

        if (action === 'accept') {
            db.get(`SELECT user1_id FROM friends WHERE id = ?`, [requestId], (err, row) => {
                if (err || !row) {
                    console.error("Error getting user1_id for accepted request:", err ? err.message : "No row found");
                    return res.status(200).json({ success: true, message: "Request accepted, but internal error with bidirectional addition." });
                }

                const user1Id = row.user1_id;

                db.run(`
                    INSERT OR IGNORE INTO friends (user1_id, user2_id, status)
                    VALUES (?, ?, 'accepted');
                `, [currentUserId, user1Id], function (err) {
                    if (err) {
                        console.error("Database error inserting reverse friend relationship:", err.message);
                    }
                    console.log(`Friend request ${requestId} accepted. Reverse relationship added: User ${currentUserId} to User ${user1Id}`);

                    db.run(`
                        UPDATE stats
                        SET friends = friends + 1
                        WHERE userId = ?;
                    `, [currentUserId], function(err) {
                        if (err) {
                            console.error(`Error updating friends count for user ${currentUserId}:`, err.message);
                        } else {
                            console.log(`Friends count incremented for user ${currentUserId}.`);
                        }
                    });

                    // Increment user1Id's friends count (the requester)
                    db.run(`
                        UPDATE stats
                        SET friends = friends + 1
                        WHERE userId = ?;
                    `, [user1Id], function(err) {
                        if (err) {
                            console.error(`Error updating friends count for user ${user1Id}:`, err.message);
                        } else {
                            console.log(`Friends count incremented for user ${user1Id}.`);
                        }
                    });
                    // --- END STATS UPDATE ON ACCEPT ---

                    res.status(200).json({ success: true, message: "Friend request accepted!" });
                });
            });
        } else { // This is the 'decline' action
            console.log(`Friend request ${requestId} declined.`);
            res.status(200).json({ success: true, message: "Friend request declined." });
        }
    });
});

// My Friends Route
app.get('/my-friends', requireLogin, (req, res) => {
    const currentUserId = req.session.user.id;

    if (!currentUserId) {
        return res.redirect('/login');
    }

    db.all(`
        SELECT
            CASE
                WHEN f.user1_id = ? THEN u2.id
                ELSE u1.id
            END AS friendId,
            CASE
                WHEN f.user1_id = ? THEN u2.username
                ELSE u1.username
            END AS username,
            CASE
                WHEN f.user1_id = ? THEN u2.email
                ELSE u1.email
            END AS email
        FROM
            friends f
        JOIN
            users u1 ON f.user1_id = u1.id
        JOIN
            users u2 ON f.user2_id = u2.id
        WHERE
            (f.user1_id = ? OR f.user2_id = ?) AND f.status = 'accepted'
        GROUP BY
            MIN(f.user1_id, f.user2_id), MAX(f.user1_id, f.user2_id)
        ORDER BY
            username ASC;
    `, [currentUserId, currentUserId, currentUserId, currentUserId, currentUserId], (err, friends) => {
        if (err) {
            console.error("Query error fetching friends:", err.message);
            return res.status(500).send("Database error fetching friends list.");
        }

        res.render('myFriends', {
            friends,
            pageTitle: 'My Friends'
        });
    });
});

// Remove Friend Route
app.post('/remove-friend', requireLogin, (req, res) => {
    const currentUserId = req.session.user.id;
    const { friendId } = req.body;

    if (!friendId) {
        return res.status(400).json({ success: false, message: 'Friend ID is missing.' });
    }

    db.run(`
        DELETE FROM friends
        WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?);
    `, [currentUserId, friendId, friendId, currentUserId], function (err) {
        if (err) {
            console.error("Database error removing friend:", err.message);
            return res.status(500).json({ success: false, message: "Could not remove friend." });
        }

        if (this.changes === 0) {
            console.warn(`Attempted to remove friend (user ${currentUserId} from ${friendId}) but no rows changed.`);
            return res.status(404).json({ success: false, message: "Friendship not found." });
        }

        db.run(`
            UPDATE stats
            SET friends = friends - 1
            WHERE userId = ? AND friends > 0;
        `, [currentUserId], function(err) {
            if (err) {
                console.error(`Error updating friends count for user ${currentUserId}:`, err.message);
            } else {
                console.log(`Friends count decremented for user ${currentUserId}.`);
            }
        });

        db.run(`
            UPDATE stats
            SET friends = friends - 1
            WHERE userId = ? AND friends > 0; -- Prevent negative counts
        `, [friendId], function(err) {
            if (err) {
                console.error(`Error updating friends count for user ${friendId}:`, err.message);
            } else {
                console.log(`Friends count decremented for user ${friendId}.`);
            }
        });
        // --- END STATS UPDATE ON REMOVE ---

        console.log(`Friendship removed: User ${currentUserId} and User ${friendId}`);
        res.status(200).json({ success: true, message: "Friend removed successfully." });
    });
});
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});