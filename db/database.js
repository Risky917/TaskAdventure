const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const db = new sqlite3.Database('./TAdatabase.db');

db.serialize(() => {

  // Tabellen aanmaken
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      profileImage TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      characterId INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      dueDate TEXT NOT NULL,
      Pending INTEGER DEFAULT 0,
      completed INTEGER DEFAULT 0,
      xp INTEGER DEFAULT 0,
      FOREIGN KEY (characterId) REFERENCES characters(id)
    )
  `);

  db.run(`
  CREATE TABLE IF NOT EXISTS characters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    name TEXT NOT NULL,
    level INTEGER DEFAULT 1,
    xp INTEGER DEFAULT 0,
    gender INTEGER DEFAULT 0,
    -- REMOVE THE LINE BELOW
    -- imagevalue TEXT,
    -- ADD THIS LINE BELOW (foreign key to character_info)
    characterInfoId INTEGER,
    FOREIGN KEY(userId) REFERENCES users(id),
    FOREIGN KEY(characterInfoId) REFERENCES character_info(id) -- This line establishes the link
  )
`);

    db.run(`
  CREATE TABLE IF NOT EXISTS character_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    baseImage TEXT UNIQUE NOT NULL, -- The initial image path that links characters to this info
    evolutionStage1Image TEXT,
    evolutionStage2Image TEXT,
    evolutionName TEXT
  )
`);

  db.run(`
    CREATE TABLE IF NOT EXISTS levelup (
      level INTEGER PRIMARY KEY,
      required_xp INTEGER NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS leaderboard (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      characterId INTEGER NOT NULL,
      rank INTEGER,
      FOREIGN KEY(characterId) REFERENCES characters(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS role_permissions (
      roleId INTEGER NOT NULL,
      permissionId INTEGER NOT NULL,
      FOREIGN KEY(roleId) REFERENCES roles(id),
      FOREIGN KEY(permissionId) REFERENCES permissions(id),
      PRIMARY KEY (roleId, permissionId)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS user_roles (
      userId INTEGER NOT NULL,
      roleId INTEGER NOT NULL,
      FOREIGN KEY(userId) REFERENCES users(id),
      FOREIGN KEY(roleId) REFERENCES roles(id),
      PRIMARY KEY (userId, roleId)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS stats (
      userId INTEGER NOT NULL,
      username TEXT UNIQUE NOT NULL,
      taskCompleted INTEGER DEFAULT 0,
      taskFailed INTEGER DEFAULT 0,
      totalXpGained INTEGER DEFAULT 0,
      friends INTEGER DEFAULT 0,
      mostXpForOneTask INTEGER DEFAULT 0,
      mostTaskIn24h INTEGER DEFAULT 0,
      dailyStreak INTEGER DEFAULT 0,
      timeSpentOnTasks INTEGER DEFAULT 0,
      FOREIGN KEY(username) REFERENCES users(username)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS classes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      code TEXT NOT NULL,
      characterId INTEGER,
      user_id INTEGER NOT NULL,
      FOREIGN KEY (characterId ) REFERENCES characters(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS class_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      classId INTEGER NOT NULL,
      userId INTEGER NOT NULL,
      joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (classId) REFERENCES classes(id),
      FOREIGN KEY (userId) REFERENCES users(id),
      UNIQUE (classId, userId)
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user1_id INTEGER NOT NULL,
        user2_id INTEGER NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user1_id) REFERENCES users(id),
        FOREIGN KEY (user2_id) REFERENCES users(id),
        UNIQUE (user1_id, user2_id)
    )
`);

   // Insert initial character info (you'll need to decide on your base images and evolutions)
  // This is just an example. You'll add more based on your characterImages array.
  db.all(`SELECT id FROM character_info WHERE baseImage = '/img/malePixel.png'`, (err, rows) => {
    if (rows.length === 0) {
      db.run(`INSERT INTO character_info (baseImage, evolutionStage1Image, evolutionStage2Image, evolutionName) VALUES (?, ?, ?, ?)`,
        ['/img/malePixel.png', '/img/malePixel2.png', '/img/malePixel3.png', 'Basic Male']);
    }
  });
  db.all(`SELECT id FROM character_info WHERE baseImage = '/img/pixelFemale.png'`, (err, rows) => {
    if (rows.length === 0) {
      db.run(`INSERT INTO character_info (baseImage, evolutionStage1Image, evolutionStage2Image, evolutionName) VALUES (?, ?, ?, ?)`,
        ['/img/pixelFemale.png', '/img/pixelFemale2.png', '/img/pixelFemale3.png', 'Basic Female']);
    }
  });
 db.all(`SELECT id FROM character_info WHERE baseImage = '/img/Hermit.png'`, (err, rows) => {
    if (rows.length === 0) {
      db.run(`INSERT INTO character_info (baseImage, evolutionStage1Image, evolutionStage2Image, evolutionName) VALUES (?, ?, ?, ?)`,
        ['/img/Hermit.png', '/img/Hermit2.png', '/img/Hermit3.png', 'Hermit']);
    }
  });
   db.all(`SELECT id FROM character_info WHERE baseImage = '/img/FeyereJoe.png'`, (err, rows) => {
    if (rows.length === 0) {
      db.run(`INSERT INTO character_info (baseImage, evolutionStage1Image, evolutionStage2Image, evolutionName) VALUES (?, ?, ?, ?)`,
        ['/img/FeyereJoe.png', '/img/FeyereJoe2.png', '/img/FeyereJoe3.png', 'Feyere Joe']);
    }
  });
   db.all(`SELECT id FROM character_info WHERE baseImage = '/img/samurai.png'`, (err, rows) => {
    if (rows.length === 0) {
      db.run(`INSERT INTO character_info (baseImage, evolutionStage1Image, evolutionStage2Image, evolutionName) VALUES (?, ?, ?, ?)`,
        ['/img/samurai.png', '/img/samurai2Evo.png', '/img/samurai3.png', 'Samurai']);
    }
  });
    db.all(`SELECT id FROM character_info WHERE baseImage = '/img/purpleguy.png'`, (err, rows) => {
    if (rows.length === 0) {
      db.run(`INSERT INTO character_info (baseImage, evolutionStage1Image, evolutionStage2Image, evolutionName) VALUES (?, ?, ?, ?)`,
        ['/img/purpleguy.png', '/img/purpleguy2.png', '/img/purpleguy3.png', 'Purple Guy']);
    }
  });

  // Rollen toevoegen
  db.all(`SELECT name FROM roles WHERE name IN ('admin', 'user', 'guest')`, (err, rows) => {
    const existingRoles = rows.map(r => r.name);
    if (!existingRoles.includes('admin')) db.run(`INSERT INTO roles (name) VALUES ('admin')`);
    if (!existingRoles.includes('user')) db.run(`INSERT INTO roles (name) VALUES ('user')`);
    if (!existingRoles.includes('guest')) db.run(`INSERT INTO roles (name) VALUES ('guest')`);
  });

  // Admin-gebruiker aanmaken
  db.get(`SELECT * FROM users WHERE username = 'admin'`, (err, user) => {
    if (err) {
      console.error("Error checking for admin user:", err);
      return;
    }
    if (!user) {
      const hashedPassword = bcrypt.hashSync('admin', 10);
      db.run(
        `INSERT INTO users (email, username, password) VALUES (?, ?, ?)`,
        ['admin@example.com', 'admin', hashedPassword],
        function (err) {
          if (err) {
            console.error("Error creating admin user:", err);
            return;
          }
          const userId = this.lastID;
          db.run(
            `INSERT INTO stats (userId, username) VALUES (?, ?)`,
            [userId, 'admin'],
            (err) => {
              if (err) console.error("❌ Kon stats niet aanmaken voor admin:", err);
            }
          );
          db.get(`SELECT id FROM roles WHERE name = 'admin'`, (err, role) => {
            if (!err && role) {
              db.run(
                `INSERT OR IGNORE INTO user_roles (userId, roleId) VALUES (?, ?)`,
                [userId, role.id]
              );
            }
          });
        }
      );
    }
  });

}); // Einde db.serialize()

// Gebruikersfuncties
function createUser(email, username, password, profileImage, callback) {
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return callback(err);
    db.run(
      `INSERT INTO users (email, username, password, profileImage) VALUES (?, ?, ?, ?)`,
      [email, username, hashedPassword, profileImage],
      function (err) {
        callback(err, this.lastID);
      }
    );
  });
}

function findUser(usernameOrEmail, callback) {
  db.get(
    `SELECT * FROM users WHERE username = ? OR email = ?`,
    [usernameOrEmail, usernameOrEmail],
    (err, row) => {
      callback(err, row);
    }
  );
}

function getTasks(userId, callback) {
  db.all(
    `SELECT * FROM tasks WHERE userId = ?`,
    [userId],
    (err, tasks) => {
      callback(err, tasks);
    }
  );
}

function getCharacterInfoByBaseImage(baseImage, callback) {
  db.get('SELECT * FROM character_info WHERE baseImage = ?', [baseImage], (err, row) => {
    callback(err, row);
  });
}

module.exports = { db, createUser, findUser, getTasks, getCharacterInfoByBaseImage };

//correct script