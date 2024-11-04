module.exports = {
  testEnvironment: 'node',  // 'jsdom' for React, 'node' for backend
  roots: ['<rootDir>/tests'], // Points to your test directory
  moduleFileExtensions: ['js', 'jsx'],
  transform: {
    '^.+\\.jsx?$': 'babel-jest',
  },
};
