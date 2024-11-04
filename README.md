# Password Manager
A client-side encrypted password manager application designed to securely store and manage user credentials for COMP6841 

## Features
- Client-Side Encryption: Uses CryptoJS for encrypting data on the client before sending it to the server.
- Secure Authentication: Implements two-factor authentication (2FA) and JSON Web Tokens (JWT) for secure access.
- Password Strength Checker: Provides users feedback on password strength.
- Two-Factor Authentication (2FA): Adds an extra layer of security during login.
## Technologies Used
- Express.js: For API routing and handling requests.
- Bcrypt: For securely hashing sensitive information.
- JWT: For secure user authentication.
- CryptoJS: For encryption and decryption.
- MySQL with MySQL Workbench: For database management.
## Installation

Clone the Repository:
- `git clone <repository-url>`
- `cd password-manager`
- `Install Dependencies:`

- `npm install`
Configure Database:
- Ensure MySQL is running and configure the database in config.js (or .env if using environment variables).
- Run the SQL schema script to initialize tables (found in setup.sql).
Run the Application:

- `npm start`
- Open up another terminal and `cd backend`
- then `node index.js` to start the backend


- Access the Application:

- Go to http://localhost:3000 in your web browser.
