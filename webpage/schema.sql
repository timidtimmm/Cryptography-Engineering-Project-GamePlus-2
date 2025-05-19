CREATE DATABASE secure_share;
USE secure_share;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(64) NOT NULL,
    role ENUM('professor', 'assistant', 'visitor') NOT NULL,
    cert_fingerprint VARCHAR(128)
);

CREATE TABLE files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    owner_id INT NOT NULL,
    wrapped_key BLOB NOT NULL,
    iv BINARY(12) NOT NULL,
    upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

CREATE TABLE audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action ENUM('login', 'upload', 'download', 'wrap', 'unwrap', 'delete'),
    file_id INT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    status ENUM('success', 'fail') NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (file_id) REFERENCES files(id)
);
