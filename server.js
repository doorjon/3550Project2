const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./totally_not_my_privateKeys.db', sqlite3.OPEN_READWRITE, (err)=>{
  if (err) return console.error(err.message);
});
const app = express();
const port = 8080;

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;
let row;
let parsedKey;

// create db table
db.run('CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT,key BLOB NOT NULL,exp INTEGER NOT NULL)');

async function generateKeyPairs() {
  keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });

  db.run('INSERT INTO keys (key, exp) VALUES (?, ?)', [JSON.stringify(keyPair.toJSON()), Math.floor(Date.now() / 3600) + 7200], (err) => {
    if (err) {
      console.error('Error inserting key into the database:', err.message);
    }
  });
}

function generateToken() {
  // retrieve key from database
  db.get('SELECT * FROM keys WHERE kid > 0;', (err, row) => {
    if (err) {
      console.error('Error retrieving key from the database:', err.message);
    }

    // parse key into usable format
    parsedKey = jose.JWK.asKey(row.key);
    parsedKey.then(function(parsedKey) {
      const payload = {
        user: 'sampleUser',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600
      };
      const options = {
        algorithm: 'RS256',
        header: {
          typ: 'JWT',
          alg: 'RS256',
          kid: parsedKey.kid
        }
      };
      
      token = jwt.sign(payload, keyPair.toPEM(true), options);
   })
   
  });

  
}

function generateExpiredJWT() {

  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp: Math.floor(Date.now() / 1000) - 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: expiredKeyPair.kid
    }
  };

  expiredToken = jwt.sign(payload, expiredKeyPair.toPEM(true), options);
}

app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.get('/.well-known/jwks.json', (req, res) => {
  const validKeys = [keyPair].filter(key => !key.expired);
  res.setHeader('Content-Type', 'application/json');
  res.json({ keys: validKeys.map(key => key.toJSON()) });
});

app.post('/auth', (req, res) => {

  if (req.query.expired === 'true'){
    return res.send(expiredToken);
  }
  res.send(token);
});

generateKeyPairs().then(() => {
  generateToken()
  generateExpiredJWT()
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});

module.exports = app;
