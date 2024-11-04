import React, { useEffect, useState, useCallback, useContext } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from '../AuthContext';
import MenuIcon from "@mui/icons-material/Menu";
import { Snackbar, Alert, Box, TextField, Button, Typography, Paper, Grid, Card, CardContent, CardActions, IconButton, LinearProgress, Dialog, DialogTitle, DialogContent, Backdrop } from "@mui/material";
import Sidebar from "./Sidebar";
import { encryptData, decryptData } from '../encryption'; 

function Dashboard() {
  const [service, setService] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [website, setWebsite] = useState('');
  const [passwordStrength, setPasswordStrength] = useState({ level: "", color: "" });
  const [passwordList, setPasswordList] = useState([]);
  const [revealedPasswords, setRevealedPasswords] = useState({});
  const [editIndex, setEditIndex] = useState(null);
  const { logout } = useContext(AuthContext);
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [masterPassword, setMasterPassword] = useState(''); 
  const [showMasterPasswordDialog, setShowMasterPasswordDialog] = useState(true); 
  const [isMasterPasswordValid, setIsMasterPasswordValid] = useState(false); 
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [snackbarSeverity, setSnackbarSeverity] = useState('success'); 
  
  const handleLogout = useCallback(() => {
    logout();
    navigate('/login');
  }, [logout, navigate]);

  const handleSnackbarClose = () => setSnackbarOpen(false);

  const validateMasterPassword = async () => {
    try {
      const response = await axios.post(`${process.env.REACT_APP_API_URL}/validate-master-password`, {
        masterPassword,
      }, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
      });

      if (response.data.success) {
        setIsMasterPasswordValid(true);
        setShowMasterPasswordDialog(false);
        setSnackbarMessage("Master password validated successfully!");
        setSnackbarSeverity("success");
      } else {
        alert("Invalid master password. Please try again.");
        setSnackbarMessage("Invalid master password. Please try again.");
        setSnackbarSeverity("error");
      }
      setSnackbarOpen(true);
    } catch (error) {
      if (error.response?.status === 403) {
        // Token expired, clear and redirect to login
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        navigate('/login'); 
      } else {
        console.error("Error validating master password", error);
        setSnackbarMessage("An error occurred while validating the master password.");
        setSnackbarSeverity("error");
        setSnackbarOpen(true);
      }
    }
  };

  const fetchPasswords = useCallback(async () => {
    // Only fetch passwords if master password is validated
    if (!isMasterPasswordValid) return; 
    const token = localStorage.getItem('token');
    if (!token) {
      handleLogout();
      return;
    }

    try {
      const response = await axios.get(`${process.env.REACT_APP_API_URL}/passwords`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!response.data || !Array.isArray(response.data)) {
        console.error("Unexpected response data format:", response.data);
        return;
      }

      const decryptedPasswords = response.data.map((passwordObj) => {
          try {
              return {
                  id: passwordObj.id,
                  service: decryptData(passwordObj.encrypted_service, masterPassword, passwordObj.iv_service),
                  username: decryptData(passwordObj.encrypted_username, masterPassword, passwordObj.iv_username),
                  password: passwordObj.encrypted_password,
                  iv_password: passwordObj.iv_password,
                  website: passwordObj.encrypted_website ? decryptData(passwordObj.encrypted_website, masterPassword, passwordObj.iv_website) : null
              };
          } catch (decryptionError) {
              console.error("Decryption failed for password:", passwordObj, decryptionError);
              return { ...passwordObj, decryptedPassword: null };
          }
      });
      setPasswordList(decryptedPasswords);
    } catch (err) {
      console.error('Error fetching passwords', err);
      if (err.response && err.response.status === 403) {
        handleLogout();
      }
    }
  }, [handleLogout, masterPassword, isMasterPasswordValid]);

  useEffect(() => {
    if (isMasterPasswordValid) fetchPasswords();
  }, [fetchPasswords, isMasterPasswordValid]);

  const handleAddOrEditPassword = async (e) => {
    e.preventDefault();
    const token = localStorage.getItem('token');

    // Encrypt all metadata
    const { encryptedData: encryptedService, iv: ivService } = encryptData(service, masterPassword);
    const { encryptedData: encryptedUsername, iv: ivUsername } = encryptData(username, masterPassword);
    const { encryptedData: encryptedPassword, iv: ivPassword } = encryptData(password, masterPassword);
    const { encryptedData: encryptedWebsite, iv: ivWebsite } = website ? encryptData(website, masterPassword) : {};

    // Send encrypted data and IVs to the server
    const payload = {
      encryptedService,
      ivService,
      encryptedUsername,
      ivUsername,
      encryptedPassword,
      ivPassword,
      encryptedWebsite,
      ivWebsite,
    };

    if (editIndex !== null) {
      try {
        const passwordId = passwordList[editIndex]?.id;
        await axios.put(`${process.env.REACT_APP_API_URL}/update-password/${passwordId}`, payload, { headers: { Authorization: `Bearer ${token}` } });
        resetForm();
        fetchPasswords();
        setSnackbarMessage("Password updated successfully!");
        setSnackbarSeverity("success");
      } catch (err) {
        console.error('Error updating password', err);
        setSnackbarMessage("Error updating password.");
        setSnackbarSeverity("error");
      }
    } else {
      try {
        await axios.post(`${process.env.REACT_APP_API_URL}/store-password`, payload, { headers: { Authorization: `Bearer ${token}` } });
        resetForm();
        fetchPasswords();
        setSnackbarMessage("Password stored successfully!");
        setSnackbarSeverity("success");
      } catch (err) {
        console.error('Error storing password', err);
        setSnackbarMessage("Error storing password.");
        setSnackbarSeverity("error");
      }
    }
    setSnackbarOpen(true);
  };

  const resetForm = () => {
      setService('');
      setUsername('');
      setPassword('');
      setWebsite('');
      setPasswordStrength({ level: "", color: "" });
      setEditIndex(null);
  };

  // Password strength checker with color
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

  const decryptPassword = (passwordObj, index) => {
      const decryptedPassword = decryptData(passwordObj.password, masterPassword, passwordObj.iv_password); // Use passwordObj.password and passwordObj.iv_password
      setRevealedPasswords((prevRevealed) => ({
          ...prevRevealed,
          [index]: decryptedPassword,
      }));

      setTimeout(() => {
          setRevealedPasswords((prevRevealed) => ({
              ...prevRevealed,
              [index]: null,
          }));
      }, 5000);
  };


  const handleEdit = (index) => {
    setEditIndex(index);
    setService(passwordList[index].service);
    setUsername(passwordList[index].username);
    setPassword('');
    setPasswordStrength({ level: "", color: "" });
  };

  const handleDelete = async (id) => {
    const token = localStorage.getItem('token');
    try {
      await axios.delete(`${process.env.REACT_APP_API_URL}/delete-password/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      fetchPasswords();
    } catch (err) {
      console.error('Error deleting password', err);
    }
  };

  const toggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };

  return (
    <Box p={4}>
      <Sidebar open={sidebarOpen} toggleSidebar={toggleSidebar} />

       <Backdrop open={showMasterPasswordDialog} style={{ zIndex: 1000, color: '#fff', backdropFilter: 'blur(5px)' }}>
        <Dialog open={showMasterPasswordDialog}>
          <DialogTitle>Enter Master Password</DialogTitle>
          <DialogContent>
            <TextField
              label="Master Password"
              type="password"
              value={masterPassword}
              onChange={(e) => setMasterPassword(e.target.value)}
              fullWidth
              required
            />
            <Button onClick={validateMasterPassword} color="primary">
              Submit
            </Button>
          </DialogContent>
        </Dialog>
      </Backdrop>


      <Snackbar open={snackbarOpen} autoHideDuration={4000} onClose={handleSnackbarClose}>
        <Alert onClose={handleSnackbarClose} severity={snackbarSeverity} sx={{ width: '100%' }}>
          {snackbarMessage}
        </Alert>
      </Snackbar>

      <Dialog open={showMasterPasswordDialog}>
        <DialogTitle>Enter Master Password</DialogTitle>
        <DialogContent>
          <TextField
            label="Master Password"
            type="password"
            value={masterPassword}
            onChange={(e) => setMasterPassword(e.target.value)}
            fullWidth
            required
          />
          <Button onClick={validateMasterPassword} color="primary">Submit</Button>
        </DialogContent>
      </Dialog>

      <Box display="flex" alignItems="center" justifyContent="center" mb={4} position="relative">
        <IconButton
          onClick={toggleSidebar}
          color="primary"
          size="large"
          sx={{ position: "absolute", left: 0 }}
        >
          <MenuIcon fontSize="large" />
        </IconButton>
        <Typography variant="h4">Dashboard</Typography>
        <Button onClick={handleLogout} variant="outlined" color="secondary" sx={{ position: "absolute", right: 0 }}>
          Logout
        </Button>
      </Box>

      <Box display="flex" justifyContent="center" alignItems="center" flexDirection="column">
        <Paper elevation={3} style={{ padding: '30px', width: '100%', maxWidth: '400px' }}>
          <Box component="form" onSubmit={handleAddOrEditPassword} display="flex" flexDirection="column" gap={2}>
            <TextField label="Service" value={service} onChange={(e) => setService(e.target.value)} required />
            <TextField label="Website (optional)" value={website} onChange={(e) => setWebsite(e.target.value)} />
            <TextField label="Username" value={username} onChange={(e) => setUsername(e.target.value)} required />
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
            <Typography variant="body2" style={{ color: passwordStrength.color }}>
              Password Strength: {passwordStrength.level}
            </Typography>
            <LinearProgress
              variant="determinate"
              value={passwordStrength.level === "Very strong" ? 100 : passwordStrength.level === "Strong" ? 80 : passwordStrength.level === "Moderate" ? 60 : passwordStrength.level === "Weak" ? 40 : 20}
              sx={{ bgcolor: passwordStrength.color, height: 6, mt: 1 }}
            />
            <Box display="flex" gap={1}>
              <Button variant="contained" color="primary" type="submit">
                {editIndex !== null ? 'Update Password' : 'Add Password'}
              </Button>
              {editIndex !== null && (
                <Button variant="outlined" color="secondary" onClick={resetForm}>
                  Cancel
                </Button>
              )}
            </Box>
          </Box>
        </Paper>
      </Box>

      <Typography variant="h5" mt={4} textAlign="center">Saved Passwords</Typography>
      <Grid container spacing={2} mt={2} justifyContent="center">
        {passwordList.map((val, index) => (
          <Grid item xs={12} sm={6} md={4} key={val.id}>
              <Card>
                  <CardContent>
                      <Typography variant="h6">{val.service}</Typography>
                      <Typography variant="body2">Username: {val.username}</Typography>
                      {val.website ? (
                        <Typography variant="body2">
                          <a href={val.website} target="_blank" rel="noopener noreferrer">
                            Visit Website
                          </a>
                        </Typography>
                      ) : (
                        <Typography variant="body2">No Website Provided</Typography>
                      )}
                      {revealedPasswords[index] ? (
                          <Typography variant="body2">Password: {revealedPasswords[index]}</Typography>
                      ) : (
                          <Button size="small" onClick={() => decryptPassword(val, index)}>
                              View Password
                          </Button>
                      )}
                  </CardContent>
                  <CardActions>
                      <Button size="small" onClick={() => handleEdit(index)}>Edit</Button>
                      <Button size="small" color="error" onClick={() => handleDelete(val.id)}>Delete</Button>
                  </CardActions>
              </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
}

export default Dashboard;
