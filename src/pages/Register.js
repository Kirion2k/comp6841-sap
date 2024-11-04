import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { TextField, Button, Typography, Box, Paper, Snackbar, Alert, LinearProgress } from '@mui/material';
import { AppTitle, Footer } from './AppTitle';

function Register() {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [passwordStrength, setPasswordStrength] = useState({ level: "", color: "" });
  const [message, setMessage] = useState('');
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarSeverity, setSnackbarSeverity] = useState('success');
  const navigate = useNavigate();
  const [masterPassword, setMasterPassword] = useState('');

  const showSnackbar = (message, severity) => {
    setMessage(message);
    setSnackbarSeverity(severity);
    setSnackbarOpen(true);
  };

  const handleRegister = async (e) => {
    e.preventDefault();

    // Password validation regex
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
      showSnackbar('Password must be at least 8 characters, contain a number and a special character', 'error');
      return;
    }

    try {
      await axios.post(`${process.env.REACT_APP_API_URL || 'http://localhost:3005'}/register`, {
        username,
        email,
        password,
        masterPassword
      });
      showSnackbar('User registered successfully!', 'success');
      navigate('/login');
    } catch (err) {
      showSnackbar(err.response?.data?.message || 'Registration failed', 'error');
    }
  };

  // Password strength checker with color and progress feedback
  const checkPasswordStrength = (password) => {
    if (password.length < 8) {
      setPasswordStrength({ level: "Too short", color: "red" });
    } else if (!/[A-Z]/.test(password) || !/[a-z]/.test(password)) {
      setPasswordStrength({ level: "Weak", color: "orange" });
    } else if (!/\d/.test(password)) {
      setPasswordStrength({ level: "Moderate", color: "yellow" });
    } else if (!/[!@#$%^&*]/.test(password)) {
      setPasswordStrength({ level: "Strong", color: "lightgreen" });
    } else {
      setPasswordStrength({ level: "Very strong", color: "green" });
    }
  };

  return (
    <Box display="flex" flexDirection="column" alignItems="center" justifyContent="center" height="100vh">
      <AppTitle />
      <Paper elevation={3} style={{ padding: '30px', maxWidth: '400px', width: '100%' }}>
        <Typography variant="h4" color="primary" gutterBottom align="center">Register</Typography>
        <Box component="form" onSubmit={handleRegister} display="flex" flexDirection="column" gap={2}>
          <TextField label="Username" value={username} onChange={(e) => setUsername(e.target.value)} required />
          <TextField label="Email" value={email} onChange={(e) => setEmail(e.target.value)} type="email" required />
          <TextField 
            label="Password" 
            type="password" 
            value={password} 
            onChange={(e) => {
              setPassword(e.target.value);
              checkPasswordStrength(e.target.value);
            }} 
            required 
          />
          <TextField
            label="Master Password"
            type="password"
            value={masterPassword}
            onChange={(e) => setMasterPassword(e.target.value)}
            required
          />
          <Typography variant="body2" style={{ color: passwordStrength.color }}>
            Password Strength: {passwordStrength.level}
          </Typography>
          <LinearProgress
            variant="determinate"
            value={passwordStrength.level === "Very strong" ? 100 : passwordStrength.level === "Strong" ? 80 : passwordStrength.level === "Moderate" ? 60 : passwordStrength.level === "Weak" ? 40 : 20}
            sx={{ bgcolor: passwordStrength.color, height: 6, mt: 1 }}
          />
          <Button variant="contained" color="primary" type="submit">Register</Button>
        </Box>
        <Typography variant="body2" align="center" style={{ marginTop: '1rem' }}>
          Already have an account? <a href="/login">Login here</a>
        </Typography>
      </Paper>
      <Snackbar open={snackbarOpen} autoHideDuration={4000} onClose={() => setSnackbarOpen(false)}>
        <Alert severity={snackbarSeverity} onClose={() => setSnackbarOpen(false)}>{message}</Alert>
      </Snackbar>
      <Footer />
    </Box>
  );
}

export default Register;
