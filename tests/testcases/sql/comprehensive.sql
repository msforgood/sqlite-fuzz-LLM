-- Comprehensive SQL test for mode 0 (basic mode)
CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT);
CREATE INDEX idx_email ON users(email);
INSERT INTO users VALUES (1, 'Alice', 'alice@example.com');
INSERT INTO users VALUES (2, 'Bob', 'bob@example.com');
SELECT COUNT(*) FROM users;
SELECT json_extract('{"name":"test"}', '$.name');
WITH RECURSIVE cnt(x) AS (SELECT 1 UNION SELECT x+1 FROM cnt WHERE x<5) SELECT * FROM cnt;
DROP TABLE users;