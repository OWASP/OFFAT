const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const db = require('./jsdb');

const app = express();

function buildCmd(host) {
  return 'ping -c 1 ' + host;
}

app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(buildCmd(host), (err, out) => res.send(out));          // VULN cmdi (via helper)
});

app.get('/file', function (req, res) {
  const name = req.params.name;
  res.sendFile(path.join('/srv/files', name));                 // VULN path traversal
});

app.get('/file-safe', function (req, res) {
  res.sendFile(path.join('/srv/files', path.basename(req.query.name)));   // SAFE
});

app.get('/user', async (req, res) => {
  const rows = await db.findByName(req.query.name);             // VULN sqli (cross-module)
  res.json(rows);
});

app.get('/proxy', async (req, res) => {
  const r = await axios.get(req.query.url);                     // VULN ssrf
  res.json(r.data);
});

app.get('/greet', (req, res) => {
  res.send(`<h1>Hello ${req.query.name}</h1>`);                 // VULN xss
});

app.get('/greet-num', (req, res) => {
  const n = parseInt(req.query.n, 10);
  res.send(`<h1>${n}</h1>`);                                     // SAFE parseInt
});

module.exports = app;
