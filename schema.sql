-- Database init
-- Note: You might need to create the database manually or run this as a superuser
-- CREATE DATABASE repair_service;

-- Connect to DB (this command works in psql, but ignored if running via driver usually, 
-- but good for documentation)
-- \c repair_service

-- Users table
CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    fio VARCHAR(255) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    login VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL
);

-- Requests table
CREATE TABLE IF NOT EXISTS requests (
    request_id SERIAL PRIMARY KEY,
    start_date DATE NOT NULL,
    home_tech_type VARCHAR(100) NOT NULL,
    home_tech_model VARCHAR(255) NOT NULL,
    problem_description TEXT NOT NULL,
    request_status VARCHAR(50) NOT NULL,
    completion_date DATE,
    repair_parts TEXT,
    master_id INTEGER REFERENCES users(user_id),
    client_id INTEGER REFERENCES users(user_id)
);

-- Comments table
CREATE TABLE IF NOT EXISTS comments (
    comment_id SERIAL PRIMARY KEY,
    message TEXT NOT NULL,
    master_id INTEGER REFERENCES users(user_id),
    request_id INTEGER REFERENCES requests(request_id)
);
