import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { TextField, Button, Typography, Box, Paper, Snackbar, Alert } from '@mui/material';
import { AppTitle, Footer } from './AppTitle';

function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showTwoFactorInput, setShowTwoFactorInput] = useState(false);
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [tempToken, setTempToken] = useState('');  
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [snackbarSeverity, setSnackbarSeverity] = useState('error'); 
  const navigate = useNavigate();

  const handleSnackbarClose = () => setSnackbarOpen(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post("http://localhost:3005/login", { username, password });
      setTempToken(response.data.token);  
      
      if (response.data.twoFactorEnabled) {
        setShowTwoFactorInput(true); 
      } else {
        localStorage.setItem("token", response.data.token);
        setSnackbarMessage("Login successful!");
        setSnackbarSeverity("success");
        setSnackbarOpen(true);
        navigate("/dashboard"); 
      }
    } catch (err) {
      console.error("Login failed:", err);
      setSnackbarMessage("Invalid credentials");
      setSnackbarSeverity("error");
      setSnackbarOpen(true);
    }
  };

  const verifyTwoFactorCode = async () => {
    try {
      const response = await axios.post(
        'http://localhost:3005/verify-totp',
        { code: twoFactorCode },
        { headers: { Authorization: `Bearer ${tempToken}` } }
      );

      if (response.data.success) {
        localStorage.setItem("token", tempToken);  
        setSnackbarMessage("Two-factor authentication verified successfully");
        setSnackbarSeverity("success");
        setSnackbarOpen(true);
        navigate('/dashboard'); 
      } else {
        setSnackbarMessage(response.data.message || "Invalid 2FA code");
        setSnackbarSeverity("error");
        setSnackbarOpen(true);
      }
    } catch (err) {
      console.error("Verification failed:", err);
      setSnackbarMessage("Failed to verify TOTP code.");
      setSnackbarSeverity("error");
      setSnackbarOpen(true);
    }
  };

  return (
    <Box display="flex" flexDirection="column" alignItems="center" justifyContent="center" height="100vh">
      <AppTitle />
      <Paper elevation={3} style={{ padding: '30px', maxWidth: '400px', width: '100%' }}>
        <Typography variant="h4" color="primary" gutterBottom align="center">Login</Typography>
        <Box component="form" onSubmit={handleLogin} display="flex" flexDirection="column" gap={2}>
          <TextField label="Username" value={username} onChange={(e) => setUsername(e.target.value)} required />
          <TextField label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          <Button variant="contained" color="primary" type="submit">Login</Button>
        </Box>

        {showTwoFactorInput && (
          <Box mt={2}>
            <Typography variant="body2">Enter 2FA Code:</Typography>
            <TextField
              value={twoFactorCode}
              onChange={(e) => setTwoFactorCode(e.target.value)}
              required
            />
            <Button onClick={verifyTwoFactorCode} variant="contained" color="primary" sx={{ mt: 1 }}>
              Submit Code
            </Button>
          </Box>
        )}
        
        <Typography variant="body2" align="center" style={{ marginTop: '1rem' }}>
          Don't have an account? <a href="/register">Register here</a>
        </Typography>
      </Paper>

      <Snackbar open={snackbarOpen} autoHideDuration={4000} onClose={handleSnackbarClose}>
        <Alert onClose={handleSnackbarClose} severity={snackbarSeverity} sx={{ width: '100%' }}>
          {snackbarMessage}
        </Alert>
      </Snackbar>
      
      <Footer />
    </Box>
  );
}

export default Login;
