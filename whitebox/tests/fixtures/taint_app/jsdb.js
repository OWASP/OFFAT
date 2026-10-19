const pool = require('./pool');

async function findByName(name) {
  const sql = "SELECT * FROM users WHERE name = '" + name + "'";
  return pool.query(sql);
}

async function findByNameSafe(name) {
  return pool.query('SELECT * FROM users WHERE name = $1', [name]);
}

module.exports = { findByName, findByNameSafe };
