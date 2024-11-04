-- Create database
CREATE DATABASE IF NOT EXISTS PasswordManager;
USE PasswordManager;

-- Users Table: Stores user information, hashed passwords, and 2FA secret
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL, 
    master_password VARCHAR(255) NOT NULL, 
    totp_secret VARCHAR(255), 
);

-- Passwords Table: Stores encrypted passwords and associated metadata
CREATE TABLE IF NOT EXISTS passwords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL, 
    encrypted_service TEXT NOT NULL, 
    iv_service TEXT NOT NULL, 
    encrypted_username TEXT NOT NULL, 
    iv_username TEXT NOT NULL, 
    encrypted_password TEXT NOT NULL, 
    iv_password TEXT NOT NULL, 
    encrypted_website TEXT, 
    iv_website TEXT, 
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for faster lookups
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_passwords_user_id ON passwords(user_id);
