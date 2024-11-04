const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const dotenv = require('dotenv');
const cors = require('cors');
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");


const { encrypt, decrypt } = require("./EncryptionHandler");

dotenv.config();

// Enable CORS
app.use(cors({ origin: 'http://localhost:3000' }));  


// MySQL Connection Pool
const db = mysql.createPool({
  host: "172.17.132.71",
  user: "remote_user",
  password: "your_password",
  database: "PasswordManager",
  port: 3306,
});

// Test the connection
db.getConnection((err, connection) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL');
  connection.release();
});

app.use(express.json());


app.post('/register', async (req, res) => {
  const { username, email, password, masterPassword } = req.body;

  if (!username || !email || !password || !masterPassword) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  // Hash and encrypt the master password before storage
  const encryptedMasterPassword = bcrypt.hashSync(masterPassword, 10);

  db.query(
    'INSERT INTO users (username, email, password_hash, master_password) VALUES (?, ?, ?, ?)',
    [username, email, hashedPassword, encryptedMasterPassword],
    (err, results) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: 'Username or email already exists' });
        }
        console.error('Database error:', err);
        return res.status(500).json({ message: 'Internal server error' });
      }
      res.status(201).json({ message: 'User registered successfully!' });
    }
  );
});

// Inside Login Endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  db.query(
    'SELECT * FROM users WHERE username = ?',
    [username],
    async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ message: 'Internal server error' });
      }

      if (results.length === 0) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }

      const user = results[0];
      const isMatch = await bcrypt.compare(password, user.password_hash);

      if (!isMatch) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }

      // Check if the user has a master password set
      const hasMasterPassword = Boolean(user.master_password);

      // If login is successful, include a flag if the master password needs verification
      const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({
        message: 'Login successful',
        token,
        needsMasterPassword: hasMasterPassword,
        twoFactorEnabled: !!user.totp_secret,
      });
    }
  );
});


// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log("No token provided");
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.log("Token verification failed:", err);
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};


app.get('/dashboard', verifyToken, (req, res) => {
  res.json({ message: 'This is a protected route', userId: req.userId });
});

app.post('/store-password', verifyToken, (req, res) => {
    const userId = req.user.id;
    const { encryptedService, ivService, encryptedUsername, ivUsername, encryptedPassword, ivPassword, encryptedWebsite, ivWebsite } = req.body;

    if (!encryptedService || !ivService || !encryptedUsername || !ivUsername || !encryptedPassword || !ivPassword) {
        return res.status(400).json({ error: 'All required fields (service, username, password) and their IVs must be provided' });
    }

    db.query(
        'INSERT INTO passwords (user_id, encrypted_service, iv_service, encrypted_username, iv_username, encrypted_password, iv_password, encrypted_website, iv_website) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [userId, encryptedService, ivService, encryptedUsername, ivUsername, encryptedPassword, ivPassword, encryptedWebsite || null, ivWebsite || null],
        (err, result) => {
            if (err) {
                console.error('Error storing password:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.status(201).json({ message: 'Password stored successfully' });
        }
    );
});

app.get('/passwords', verifyToken, (req, res) => {
    const userId = req.user.id;

    db.query(
        'SELECT id, encrypted_service, iv_service, encrypted_username, iv_username, encrypted_password, iv_password, encrypted_website, iv_website FROM passwords WHERE user_id = ?',
        [userId],
        (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Internal server error' });
            }
            res.status(200).json(results);
        }
    );
});

app.post('/decrypt-password', verifyToken, (req, res) => {
  const { masterPassword, encryptedData, iv } = req.body;

  db.query('SELECT master_password FROM users WHERE id = ?', [req.user.id], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(500).json({ message: 'Internal server error' });
    }

    const isMasterValid = await bcrypt.compare(masterPassword, results[0].master_password);
    if (!isMasterValid) {
      return res.status(401).json({ message: 'Invalid master password' });
    }

    // Decrypt only if master password is validated
    try {
      const decryptedPassword = decrypt({ password: encryptedData, iv });
      res.status(200).json({ decryptedPassword });
    } catch (error) {
      console.error('Error decrypting password:', error);
      res.status(500).json({ error: 'Decryption error' });
    }
  });
});


// Delete Password
app.delete('/delete-password/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM passwords WHERE id = ?', [id], (err, result) => {
    if (err) {
      console.error('Error deleting password:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
    res.status(200).json({ message: 'Password deleted successfully' });
  });
});

app.put('/update-password/:id', verifyToken, (req, res) => {
    const passwordId = req.params.id;
    const { encryptedService, ivService, encryptedUsername, ivUsername, encryptedPassword, ivPassword, encryptedWebsite, ivWebsite } = req.body;

    if (!encryptedService || !ivService || !encryptedUsername || !ivUsername || !encryptedPassword || !ivPassword) {
        return res.status(400).json({ error: 'All required fields (service, username, password) and their IVs must be provided' });
    }

    db.query(
        'UPDATE passwords SET encrypted_service = ?, iv_service = ?, encrypted_username = ?, iv_username = ?, encrypted_password = ?, iv_password = ?, encrypted_website = ?, iv_website = ? WHERE id = ?',
        [encryptedService, ivService, encryptedUsername, ivUsername, encryptedPassword, ivPassword, encryptedWebsite || null, ivWebsite || null, passwordId],
        (err, result) => {
            if (err) {
                console.error('Error updating password:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.status(200).json({ message: 'Password updated successfully' });
        }
    );
});

app.post("/enable-2fa", verifyToken, async (req, res) => {
  const secret = speakeasy.generateSecret({ name: "PasswordManagerApp" });
  const otpAuthUrl = secret.otpauth_url;

  qrcode.toDataURL(otpAuthUrl, (err, dataUrl) => {
    if (err) {
      console.error("Error generating QR code:", err);
      return res.status(500).json({ message: "Failed to generate QR code" });
    }
    res.json({ message: "2FA setup pending verification", qrcode: dataUrl, tempSecret: secret.base32 });
  });
});

app.post("/confirm-2fa", verifyToken, (req, res) => {
  const { code, tempSecret } = req.body;

  // Verify the provided TOTP code with the tempSecret.
  const verified = speakeasy.totp.verify({
    secret: tempSecret,
    encoding: "base32",
    token: code,
  });

  if (verified) {
    // Only store the 2FA secret after successful verification.
    db.query("UPDATE users SET totp_secret = ? WHERE id = ?", [tempSecret, req.user.id], (err) => {
      if (err) {
        console.error("Error saving TOTP secret:", err);
        return res.status(500).json({ message: "Failed to save TOTP secret" });
      }
      res.json({ success: true, message: "2FA enabled successfully" });
    });
  } else {
    res.status(401).json({ success: false, message: "Invalid TOTP code" });
  }
});



app.post("/verify-2fa", verifyToken, (req, res) => {
  const { token } = req.body;

  db.query("SELECT totp_secret FROM users WHERE id = ?", [req.user.id], (err, results) => {
    if (err || results.length === 0) {
      return res.status(500).json({ success: false, message: "Error retrieving TOTP secret" });
    }

    const verified = speakeasy.totp.verify({
      secret: results[0].totp_secret,
      encoding: "base32",
      token,
    });

    if (verified) {
      return res.json({ success: true, message: "TOTP verified successfully" });
    } else {
      return res.status(401).json({ success: false, message: "Invalid TOTP code" });
    }
  });
});

// Endpoint to verify TOTP code
app.post('/verify-totp', verifyToken, (req, res) => {
  const { code } = req.body;
  const userId = req.user.id;

  // Retrieve the user's TOTP secret
  db.query('SELECT totp_secret FROM users WHERE id = ?', [userId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(500).json({ message: 'Internal server error' });
    }

    const { totp_secret } = results[0];
    const verified = speakeasy.totp.verify({
      secret: totp_secret,
      encoding: 'base32',
      token: code,
    });

    if (verified) {
      return res.json({ success: true, message: 'TOTP verified successfully' });
    } else {
      return res.status(401).json({ success: false, message: 'Invalid TOTP code' });
    }
  });
});

app.post("/disable-2fa", verifyToken, (req, res) => {
  db.query("UPDATE users SET totp_secret = NULL WHERE id = ?", [req.user.id], (err) => {
    if (err) {
      console.error("Error disabling TOTP:", err);
      return res.status(500).json({ message: "Failed to disable TOTP" });
    }
    res.json({ message: "2FA disabled successfully" });
  });
});


// Endpoint to get the 2FA status
app.get("/get-2fa-status", verifyToken, (req, res) => {
  db.query("SELECT totp_secret FROM users WHERE id = ?", [req.user.id], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching 2FA status" });
    }
    // True if TOTP secret exists
    const twoFactorEnabled = !!results[0].totp_secret; 
    res.json({ twoFactorEnabled });
  });
});

app.post('/validate-master-password', verifyToken, (req, res) => {
  const { masterPassword } = req.body;

  db.query('SELECT master_password FROM users WHERE id = ?', [req.user.id], (err, results) => {
    if (err || results.length === 0) {
      return res.status(500).json({ message: 'Internal server error' });
    }

    const storedMasterPasswordHash = results[0].master_password;

    // Use bcrypt.compare to check if the entered password matches the stored hash
    bcrypt.compare(masterPassword, storedMasterPasswordHash, (compareErr, isMatch) => {
      if (compareErr) {
        console.error('Error comparing master password:', compareErr);
        return res.status(500).json({ message: 'Comparison error' });
      }

      if (isMatch) {
        return res.json({ success: true });
      } else {
        return res.status(401).json({ message: 'Invalid master password' });
      }
    });
  });
});

module.exports = app;

// Start the server
app.listen(3005, () => console.log('Server running on port 3003'));




