// init-db.js
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const dbFile = './users.db';

const db = new sqlite3.Database(dbFile, (err) => {
  if (err) return console.error("DB open error:", err);
  console.log("Connected to", dbFile);
});

db.serialize(async () => {
  db.run("DROP TABLE IF EXISTS users;");
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL
    );
  `);

  const insert = db.prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)");

  const users = [
    {u: 'alice', p: 'alicepass', r: 'user'},
    {u: 'admin', p: 'adminpass', r: 'admin'}
  ];

  for (const usr of users) {
    const hash = bcrypt.hashSync(usr.p, 10);
    insert.run(usr.u, hash, usr.r);
  }
  insert.finalize();
  console.log("✅ users table created with sample accounts:");
  console.log("   - alice / alicepass (role: user)");
  console.log("   - admin / adminpass (role: admin)");
});

db.close();
