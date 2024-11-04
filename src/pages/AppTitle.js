import React from 'react';
import { Typography, Box } from '@mui/material';

export const AppTitle = () => (
  <Box textAlign="center" mb={4}>
    <Typography variant="h3" color="primary" fontWeight="bold">
      Password Manager
    </Typography>
  </Box>
);

export const Footer = () => (
  <Box mt={6} textAlign="center">
    <Typography variant="body2" color="textSecondary">
      © This web app was made by Leo Xu z5439502 for 24t3 COMP6841 "Something Awesome Project" 
    </Typography>
  </Box>
);
