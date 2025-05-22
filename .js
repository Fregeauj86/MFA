// Multi-Factor Authentication (MFA) Example

// Setup & Dependencies
// Run the following commands to set up:
// npm init -y
// npm install express bcryptjs speakeasy qrcode express-session body-parser

// Basic Express Server Setup
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(
  session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
      sameSite: 'strict', // Prevent CSRF
    },
  })
);

app.listen(3000, () => console.log('Server started on http://localhost:3000'));

// In-Memory User Store (for demo purposes only)
const users = {}; // username: { passwordHash, mfaSecret }

// User Registration Route
app.get('/register', (req, res) => {
  res.send(`
    <form method="post">
      Username: <input name="username" required /><br/>
      Password: <input name="password" type="password" required /><br/>
      <button type="submit">Register</button>
    </form>
  `);
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.send('Invalid input');
  if (users[username]) return res.send('User already exists');

  try {
    const passwordHash = await bcrypt.hash(password, 10);

    // Generate MFA secret
    const mfaSecret = speakeasy.generateSecret({ length: 20 });

    // Store user
    users[username] = { passwordHash, mfaSecret: mfaSecret.base32 };

    // Generate QR code URL for Google Authenticator
    const otpauthUrl = speakeasy.otpauthURL({
      secret: mfaSecret.ascii,
      label: `MyApp (${username})`,
      issuer: 'MyApp',
    });

    qrcode.toDataURL(otpauthUrl, (err, dataUrl) => {
      if (err) {
        console.error(err);
        return res.send('Error generating QR code');
      }
      res.send(`
        <p>Scan this QR code with your Authenticator app:</p>
        <img src="${dataUrl}" /><br/>
        <p>Then <a href="/login">Login here</a></p>
      `);
    });
  } catch (error) {
    console.error(error);
    res.send('Error registering user');
  }
});

// User Login (Password Step)
app.get('/login', (req, res) => {
  res.send(`
    <form method="post">
      Username: <input name="username" required /><br/>
      Password: <input name="password" type="password" required /><br/>
      <button type="submit">Login</button>
    </form>
  `);
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.send('Invalid input');

  const user = users[username];
  if (!user) return res.send('User not found');

  try {
    const passwordValid = await bcrypt.compare(password, user.passwordHash);
    if (!passwordValid) return res.send('Incorrect password');

    // Save username in session for MFA verification next
    req.session.tempUser = username;

    res.redirect('/mfa');
  } catch (error) {
    console.error(error);
    res.send('Error during login');
  }
});

// MFA Verification
app.get('/mfa', (req, res) => {
  if (!req.session.tempUser) return res.redirect('/login');

  res.send(`
    <form method="post">
      Enter MFA Code from Authenticator app: <input name="token" required /><br/>
      <button type="submit">Verify</button>
    </form>
  `);
});

app.post('/mfa', (req, res) => {
  const username = req.session.tempUser;
  if (!username) return res.redirect('/login');

  const user = users[username];
  const { token } = req.body;

  const verified = speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token,
  });

  if (verified) {
    req.session.user = username; // User fully logged in
    delete req.session.tempUser;
    res.send(`Welcome, ${username}! You are logged in.`);
  } else {
    res.send('Invalid MFA token. <a href="/mfa">Try again</a>');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.send('Logged out. <a href="/login">Login</a>');
});
