import React, { useState, useEffect } from "react";
import { Drawer, List, ListItem, ListItemText, Switch, Typography, Box, Button, Modal, Backdrop, Fade, TextField, Snackbar, Alert } from "@mui/material";
import axios from "axios";

function Sidebar({ open, toggleSidebar }) {
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false);
  const [qrCode, setQrCode] = useState("");
  const [twoFactorToken, setTwoFactorToken] = useState("");
  const [tempSecret, setTempSecret] = useState("");
  const [openModal, setOpenModal] = useState(false);

  // Snackbar states for displaying messages
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState("");
  const [snackbarSeverity, setSnackbarSeverity] = useState("success"); 

  // Fetch 2FA status from the server when the sidebar opens
  const fetchTwoFactorStatus = async () => {
    try {
      const response = await axios.get("http://localhost:3005/get-2fa-status", {
        headers: { Authorization: `Bearer ${localStorage.getItem("token")}` },
      });
      setTwoFactorEnabled(response.data.twoFactorEnabled);
    } catch (error) {
      console.error("Error fetching 2FA status:", error);
    }
  };

  useEffect(() => {
    if (open) {
      fetchTwoFactorStatus();
    }
  }, [open]);

  const handleToggle2FA = async () => {
    if (!twoFactorEnabled) {
      try {
        const response = await axios.post("http://localhost:3005/enable-2fa", {}, {
          headers: { Authorization: `Bearer ${localStorage.getItem("token")}` },
        });
        setQrCode(response.data.qrcode);
        setTempSecret(response.data.tempSecret);
        setOpenModal(true);
      } catch (error) {
        console.error("Error enabling 2FA:", error);
        showSnackbar("Error enabling 2FA.", "error");
      }
    } else {
      try {
        await axios.post("http://localhost:3005/disable-2fa", {}, {
          headers: { Authorization: `Bearer ${localStorage.getItem("token")}` },
        });
        setTwoFactorEnabled(false);
        setQrCode("");
        showSnackbar("2FA disabled successfully.", "success");
      } catch (error) {
        console.error("Error disabling 2FA:", error);
        showSnackbar("Error disabling 2FA.", "error");
      }
    }
  };

  const handleVerify2FA = async () => {
    try {
      const response = await axios.post(
        "http://localhost:3005/confirm-2fa",
        { code: twoFactorToken, tempSecret },
        { headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } }
      );

      if (response.data.success) {
        showSnackbar("2FA enabled successfully.", "success");
        setTwoFactorEnabled(true);
        setQrCode("");
        setOpenModal(false);
      } else {
        showSnackbar(response.data.message, "error");
      }
    } catch (error) {
      console.error("2FA verification failed:", error);
      showSnackbar("2FA verification failed.", "error");
    }
  };

  const showSnackbar = (message, severity) => {
    setSnackbarMessage(message);
    setSnackbarSeverity(severity);
    setSnackbarOpen(true);
  };

  return (
    <>
      <Drawer anchor="left" open={open} onClose={() => { toggleSidebar(); fetchTwoFactorStatus(); }}>
        <Box p={3} width="250px" role="presentation">
          <Typography variant="h6">Settings</Typography>
          <List>
            <ListItem>
              <ListItemText primary="Two-Factor Authentication" />
              <Switch checked={twoFactorEnabled} onChange={handleToggle2FA} />
            </ListItem>
          </List>
        </Box>
      </Drawer>

      {/* 2FA Modal */}
      <Modal
        open={openModal}
        onClose={() => setOpenModal(false)}
        closeAfterTransition
        BackdropComponent={Backdrop}
        BackdropProps={{ timeout: 500 }}
      >
        <Fade in={openModal}>
          <Box
            sx={{
              position: 'absolute',
              top: '50%',
              left: '50%',
              transform: 'translate(-50%, -50%)',
              width: 400,
              bgcolor: 'background.paper',
              boxShadow: 24,
              p: 4,
              borderRadius: 2,
              textAlign: 'center',
            }}
          >
            <Typography variant="h6" gutterBottom>Enable Two-Factor Authentication</Typography>
            {qrCode && (
              <>
                <Typography variant="subtitle1">Scan QR Code</Typography>
                <img src={qrCode} alt="QR Code for TOTP" style={{ width: "100%", marginTop: "10px" }} />
                <Typography variant="caption" display="block" gutterBottom>
                  Scan this QR code in your authenticator app.
                </Typography>
                <TextField
                  fullWidth
                  label="Enter 2FA Code"
                  value={twoFactorToken}
                  onChange={(e) => setTwoFactorToken(e.target.value)}
                  margin="normal"
                />
                <Button onClick={handleVerify2FA} variant="contained" color="primary" fullWidth>
                  Verify 2FA Code
                </Button>
              </>
            )}
          </Box>
        </Fade>
      </Modal>

      {/* Snackbar for feedback messages */}
      <Snackbar
        open={snackbarOpen}
        autoHideDuration={4000}
        onClose={() => setSnackbarOpen(false)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert onClose={() => setSnackbarOpen(false)} severity={snackbarSeverity} sx={{ width: '100%' }}>
          {snackbarMessage}
        </Alert>
      </Snackbar>
    </>
  );
}

export default Sidebar;
