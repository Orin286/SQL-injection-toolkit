-- Test database setup for SQL injection testing
-- WARNING: This creates intentionally vulnerable structures for educational purposes

CREATE DATABASE IF NOT EXISTS testdb;
USE testdb;

-- Users table
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(50) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user'
);

-- Insert sample users
INSERT INTO users (username, password, email, role) VALUES
('admin', 'admin123', 'admin@test.com', 'admin'),
('user1', 'password1', 'user1@test.com', 'user'),
('user2', 'password2', 'user2@test.com', 'user'),
('test', 'test123', 'test@test.com', 'user');

-- Products table
CREATE TABLE products (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2),
    category VARCHAR(50)
);

-- Insert sample products
INSERT INTO products (name, description, price, category) VALUES
('Laptop', 'High performance laptop', 999.99, 'Electronics'),
('Mouse', 'Wireless optical mouse', 29.99, 'Electronics'),
('Keyboard', 'Mechanical keyboard', 79.99, 'Electronics'),
('Monitor', '24 inch HD monitor', 199.99, 'Electronics'),
('Book', 'SQL Injection Guide', 29.99, 'Books');

-- Orders table
CREATE TABLE orders (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    product_id INT,
    quantity INT,
    order_date DATE,
    total DECIMAL(10,2),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Insert sample orders
INSERT INTO orders (user_id, product_id, quantity, order_date, total) VALUES
(1, 1, 1, '2023-01-15', 999.99),
(2, 2, 2, '2023-01-16', 59.98),
(3, 3, 1, '2023-01-17', 79.99),
(1, 4, 1, '2023-01-18', 199.99);

-- Create some views for testing
CREATE VIEW user_orders AS
SELECT u.username, p.name, o.quantity, o.total, o.order_date
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN products p ON o.product_id = p.id;

-- Create stored procedure for testing
DELIMITER //
CREATE PROCEDURE GetUserOrders(IN userId INT)
BEGIN
    SELECT u.username, p.name, o.quantity, o.total
    FROM users u
    JOIN orders o ON u.id = o.user_id
    JOIN products p ON o.product_id = p.id
    WHERE u.id = userId;
END //
DELIMITER ;

-- Grant permissions (for testing)
GRANT ALL PRIVILEGES ON testdb.* TO 'root'@'localhost';
FLUSH PRIVILEGES;
