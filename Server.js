const express = require('express');
const exphbs = require('express-handlebars');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');

const { db, createUser, findUser, getTasks } = require('./db/database');

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.render('Login', { error: 'Je moet eerst inloggen om deze pagina te bekijken.' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.render('Login', { error: 'Je moet eerst inloggen om deze pagina te bekijken.' });
  }

  const userId = req.session.user.id;

  db.get(`
    SELECT r.name FROM roles r
    INNER JOIN user_roles ur ON ur.roleId = r.id
    WHERE ur.userId = ?
  `, [userId], (err, row) => {
    if (err || !row || row.name !== 'admin') {
      return res.render('Login', { error: 'Je hebt geen toegang tot deze pagina. Je moet een admin zijn.' });
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
        return options.fn(this);  // Render the block if the values are equal
      }
      return options.inverse(this);  // Otherwise, render the inverse block
    },
    lookupCharacter: (characters, id) => {
      // Find the character by the given ID
      return characters.find(character => character.id == id);
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
    secure: false,  // Set this to true in production with HTTPS
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
app.get('/home', requireLogin, (req, res) => {
  const userId = req.session.user.id;

  db.all('SELECT * FROM characters WHERE userId = ?', [userId], (err, characters) => {
    if (err) return res.status(500).send('Error fetching characters');

    if (!characters || characters.length === 0) {
      return res.render('Home', {
        user: req.session.user,
        characters: [],
        tasks: [],
        noCharacter: true
      });
    }

    // Make sure characterId is valid
    const characterId = parseInt(req.query.characterId) || characters[0].id;
    const selectedCharacter = characters.find(c => c.id === characterId);

    if (!selectedCharacter) {
      return res.status(404).send('Character not found');
    }

    db.all('SELECT * FROM tasks WHERE characterId = ? AND pending = 1', [characterId], (err, tasks) => {
      if (err) return res.status(500).send('Error fetching tasks');

      res.render('Home', {
        user: req.session.user,
        characters,
        tasks,
        noCharacter: false,
        selectedCharacterId: characterId,
        xp: selectedCharacter.xp,
        level: selectedCharacter.level
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
    console.log("Invalid input", { userId, characterId, xpGained });
    return res.status(400).json({ error: 'Invalid input' });
  }

  console.log(`User ${userId} gaining ${xpGained} XP for character ${characterId}`);

  db.get(
    'SELECT xp, level FROM characters WHERE id = ? AND userId = ?',
    [characterId, userId],
    (err, character) => {
      if (err) {
        console.error("DB SELECT error:", err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (!character) {
        console.warn("Character not found:", characterId);
        return res.status(404).json({ error: 'Character not found' });
      }

      let newXP = character.xp + xpGained;
      let newLevel = character.level;
      let leveledUp = false;

      const xpThreshold = 100;

      while (newXP >= xpThreshold) {
        newLevel++;
        newXP -= xpThreshold;
        leveledUp = true;
      }

      console.log(`Updating character ${characterId} — New XP: ${newXP}, Level: ${newLevel}`);

      db.run(
        'UPDATE characters SET xp = ?, level = ? WHERE id = ? AND userId = ?',
        [newXP, newLevel, characterId, userId],
        function (updateErr) {
          if (updateErr) {
            console.error("DB UPDATE error:", updateErr);
            return res.status(500).json({ error: 'Failed to update XP' });
          }

          console.log(`Rows updated: ${this.changes}`);

          if (this.changes === 0) {
            return res.status(404).json({ error: 'Character not updated (not found?)' });
          }

          res.json({ xp: newXP, level: newLevel, leveledUp });
        }
      );
    }
  );
});




// Taak voltooien + XP toekennen
app.post('/task/complete/:id', requireLogin, (req, res) => {
  const taskId = req.params.id;
  const characterId = req.query.characterId;

  if (!characterId) return res.status(400).send('characterId ontbreekt');

  db.get('SELECT * FROM tasks WHERE id = ?', [taskId], (err, task) => {
    if (err || !task) return res.status(500).send('Taak niet gevonden');

    const taskXp = Number(task.xp) || 0;

    db.get('SELECT * FROM characters WHERE id = ?', [characterId], (err, character) => {
      if (err || !character) return res.status(500).send('Character niet gevonden');

      const userId = character.userId;
      const newXp = (character.xp || 0) + taskXp;
      let newLevel = character.level || 1;
      const requiredXp = 100;

      while (newXp >= newLevel * requiredXp) {
        newLevel++;
      }

      db.run(
        'UPDATE characters SET xp = ?, level = ? WHERE id = ?',
        [newXp, newLevel, characterId],
        function (err) {
          if (err) return res.status(500).send('Update character faalde');

          db.get('SELECT * FROM stats WHERE userId = ?', [userId], (err, stats) => {
            if (err || !stats) {
              console.warn('Stats niet gevonden voor userId:', userId);
              return res.redirect('/home?characterId=' + characterId);
            }

            const updatedTaskCompleted = (stats.taskCompleted || 0) + 1;
            const updatedXp = (stats.totalXpGained || 0) + taskXp;

            // ✅ Bepaal of deze taak de meeste XP tot nu toe heeft opgeleverd
            const updatedMostXp = Math.max(taskXp, stats.mostXpForOneTask || 0);

            db.run(
              'UPDATE stats SET taskCompleted = ?, totalXpGained = ?, mostXpForOneTask = ? WHERE userId = ?',
              [updatedTaskCompleted, updatedXp, updatedMostXp, userId],
              (err) => {
                if (err) console.error('Fout bij updaten van stats:', err);

                db.run(
                  'UPDATE tasks SET completed = 1 WHERE id = ?',
                  [taskId],
                  function (err) {
                    if (err) return res.status(500).send('Taak voltooien faalde');

                    res.redirect('/home?characterId=' + characterId); // Redirect naar de home pagina

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
  const username =req.session.user?.username;
  // Fetch stats for the logged-in user
  db.get('SELECT * FROM stats WHERE username = ?', [username], (err, stat) => {
    if (err) {
      console.error('Error fetching stats:', err);
      return res.status(500).send('Error fetching stats');
    }
    //Render the "Stats" view with stats 
    res.render('Stats', { stats: stat });
  });
});


// Task Manager
app.get('/Taskmanager', requireLogin, (req, res) => {
  const userId = req.session.user.id;

  db.all('SELECT * FROM characters WHERE userId = ?', [userId], (err, characters) => {
    if (err) return res.status(500).send('Error loading characters');
    if (characters.length === 0) return res.render('Taskmanager', { characters: [], tasks: [] });

    const characterIds = characters.map(c => c.id);
    const placeholders = characterIds.map(() => '?').join(',');

    db.all(
      `
      SELECT tasks.*, characters.name AS characterName 
      FROM tasks 
      JOIN characters ON tasks.characterId = characters.id 
      WHERE tasks.characterId IN (${placeholders})
      `,
      characterIds,
      (err, tasks) => {
        if (err) return res.status(500).send('Error loading tasks');
        res.render('Taskmanager', { characters, tasks });
      }
    );
  });
});

// Handle task creation
app.post('/Taskmanager', requireLogin, (req, res) => {
  const { taskName, taskDeadline, taskDescription, characterId, taskXp } = req.body;

db.run(
  `INSERT INTO tasks (title, description, dueDate, completed, characterId, xp) VALUES (?, ?, ?, 0, ?, ?)`,
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
    if (err) return res.status(500).send('Error accepting task');
    res.redirect('/Taskmanager');
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
app.get('/Login', (req, res) => res.render('Login'));

app.post('/Login', (req, res) => {
  const { username, password } = req.body;
  findUser(username, (err, user) => {
    if (err || !user) return res.render('Login', { error: 'Gebruiker niet gevonden.' });
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) return res.render('Login', { error: 'Wachtwoord incorrect.' });
      req.session.user = user;
      res.redirect('/home');
    });
  });
});

// Create Account
app.get('/CreateAccount', (req, res) => res.render('CreateAccount'));

app.post('/CreateAccount', (req, res) => {
  const { email, username, password, confirmPassword } = req.body;

  // Basic password confirmation check
  if (password !== confirmPassword) {
    return res.render('CreateAccount', { error: 'Passwords do not match.' });
  }

  // Password strength check
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{6,}$/;
  if (!passwordRegex.test(password)) {
    return res.render('CreateAccount', {
      error: 'Password must be at least 6 characters long and include one uppercase letter, one lowercase letter, and one special character.',
    });
  }

  // Check if username or email already exists
  db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], (err, existingUser) => {
    if (err) {
      return res.render('CreateAccount', { error: 'An error has occurred. Please try again.' });
    }

    if (existingUser) {
      return res.render('CreateAccount', { error: 'Username or e-mail already exists.' });
    }

    // Create user
    createUser(email, username, password, (err, userId) => {
      if (err) {
        return res.render('CreateAccount', { error: 'An error occurred while trying to create your account.' });
      }

      // Get role ID for "user"
      db.get('SELECT id FROM roles WHERE name = ?', ['user'], (err, roleRow) => {
        if (err || !roleRow) {
          req.session.user = { id: userId, username, email };
          return res.redirect('/CharacterCreation');
        }

        const roleId = roleRow.id;

        // Assign the "user" role to the new user
        db.run('INSERT INTO user_roles (userId, roleId) VALUES (?, ?)', [userId, roleId], (err) => {
          if (err) {
            console.error('Failed to assign role:', err);
          }
          db.run(
            `INSERT INTO stats (userId, username) VALUES (?, ?)`,
            [userId, username],
            (err) => {
              if (err) {
                console.error("❌ Kon stats niet aanmaken voor nieuwe gebruiker:", err);
                // Hier kun je eventueel res.render met foutmelding doen
                // maar we gaan gewoon verder met account creatie
              }

              req.session.user = { id: userId, username, email };
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
      c.id AS characterId, c.name AS characterName,
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
          name: row.characterName
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

    res.render('AdminPanel', { users: Object.values(usersMap) });
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


  // Focus Mode route
  app.get('/FocusMode', requireLogin, (req, res) => {
    res.render('FocusMode');
  });

  // Settings route
  app.get('/Settings', requireLogin, (req, res) => {
    const user = req.session.user;
    res.render('Settings', { user });
  });

  // Handle change password request
  app.post('/Settings/changePassword', requireLogin, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const user = req.session.user;

  findUser(user.username, (err, dbUser) => {
    if (err || !dbUser) {
      return res.render('Settings', { 
        alert: { type: 'error', message: 'User not found' }
      });
    }

    bcrypt.compare(currentPassword, dbUser.password, (err, isMatch) => {
      if (err || !isMatch) {
        return res.render('Settings', { 
          alert: { type: 'error', message: 'Incorrect current password' }
        });
      }

      bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
        if (err) {
          return res.render('Settings', { 
            alert: { type: 'error', message: 'Error hashing new password' }
          });
        }

        db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id], (err) => {
          if (err) {
            return res.render('Settings', { 
              alert: { type: 'error', message: 'Error updating password' }
            });
          }

          res.render('Settings', { 
            alert: { type: 'success', message: 'Password updated successfully' }
          });
        });
      });
    });
  });
});

  // Handle account removal
  app.post('/Settings/removeAccount', requireLogin, (req, res) => {
    const user = req.session.user;

  db.run('DELETE FROM users WHERE id = ?', [user.id], (err) => {
    if (err) {
      return res.render('Settings', { 
        alert: { type: 'error', message: 'Error deleting account' }
      });
    }

    db.run('DELETE FROM tasks WHERE userId = ?', [user.id], (err) => {
      if (err) {
        return res.render('Settings', { 
          alert: { type: 'error', message: 'Error deleting tasks' }
        });
      }

      req.session.destroy(() => {
        return res.render('Settings', { 
          alert: { type: 'success', message: 'Your account has been successfully deleted.' }
        });
    });
  });
});
});
// Access Rights and Permissions link
app.get('/access-rights', (req, res) => {
  res.redirect('https://en.wikipedia.org/wiki/Access_control');
});

app.get('/leaderboard', (req, res) => {
  db.all('SELECT name, xp, imagevalue FROM characters ORDER BY xp DESC LIMIT 10', [], (err, rows) => {
    if (err) {
      console.error("Query error:", err.message);
      return res.status(500).send("Database error");
    }

    const top3 = rows.slice(0, 3);
    const others = rows.slice(3);

    res.render('LeaderBoard', { top3, others });
  });
});

app.post('/admin/delete-user', requireAdmin, (req, res) => {
  const { userId } = req.body;
  db.run(`DELETE FROM users WHERE id = ?`, [userId], err => {
    if (err) return res.status(500).send('Error deleting user');
    res.redirect('/AdminPanel');
  });
});

// Character Creation
app.get('/CharacterCreation', requireLogin, (req, res) => res.render('CharacterCreation'));

app.post('/CharacterCreation', (req, res) => {
  const { name, gender, imagevalue } = req.body;
  const userId = req.session.user?.id;

  if (!userId) {
    return res.status(401).send("Unauthorized: You must be logged in.");
  }

  // Insert into the database
  db.run(
    'INSERT INTO characters (userId, name, gender, imagevalue) VALUES (?, ?, ?, ?)',
    [userId, name, gender, imagevalue],
    function (err) {
      if (err) {
        console.error('Error during DB insert:', err.message);
        return res.status(500).send('Error adding character to the database');
      }

      // Return success message as JSON
      return res.json({ success: true, message: 'Character created successfully!' });
    }
  );
});

app.get('/profile', requireLogin, (req, res) => {
  const user = req.session.user;

  db.get(`SELECT username, email FROM users WHERE id = ?`, [user.id], (err, row) => {
    if (err) {
      return res.status(500).send('Fout bij ophalen profiel.');
    }

    res.render('Profile', { user: row });
  });
});


app.post('/profile/update', requireLogin, (req, res) => {
  const { username, email } = req.body;
  const userId = req.session.user.id;

  if (!username || !email) {
    return res.status(400).json({ success: false, message: 'Alle velden zijn verplicht!' });
  }

  const checkSql = `SELECT id FROM users WHERE username = ? AND id != ?`;
  db.get(checkSql, [username, userId], (err, row) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Databasefout.' });
    }

    if (row) {
      return res.status(400).json({ success: false, message: 'Gebruikersnaam al in gebruik.' });
    }

    const getOldUsernameSql = `SELECT username FROM users WHERE id = ?`;
    db.get(getOldUsernameSql, [userId], (err, user) => {
      if (err || !user) {
        return res.status(500).json({ success: false, message: 'Gebruiker niet gevonden.' });
      }

      const oldUsername = user.username;

      const updateUserSql = `UPDATE users SET username = ?, email = ? WHERE id = ?`;
      db.run(updateUserSql, [username, email, userId], function (err) {
        if (err) {
          return res.status(500).json({ success: false, message: 'Fout bij gebruikersupdate.' });
        }

        const updateStatsSql = `UPDATE stats SET username = ? WHERE username = ?`;
        db.run(updateStatsSql, [username, oldUsername], function (err) {
          if (err) {
            return res.status(500).json({ success: false, message: 'Fout bij stats-update.' });
          }

          req.session.user.username = username;
          req.session.user.email = email;

          return res.json({ success: true, message: 'Profiel succesvol bijgewerkt.' });
        });
      });
    });
  });
});

app.get('/reset-password', (req, res) => {
  res.render('reset-password');
});
app.post('/reset-password', (req, res) => {
  const { username, newPassword } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.render('reset-password', { error: 'Databasefout' });
    if (!user) return res.render('reset-password', { error: 'Gebruiker niet gevonden' });

    const hashed = bcrypt.hashSync(newPassword, 10);

    db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, user.id], (err2) => {
      if (err2) {
        return res.render('reset-password', { error: 'Kon wachtwoord niet updaten' });
      }
      res.render('reset-password', { success: 'Wachtwoord succesvol aangepast' });
      res.redirect('/Login?reset=success');
    });
  });
});
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});