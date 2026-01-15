CREATE TABLE IF NOT EXISTS accounts(
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_plain TEXT NOT NULL,
    password_hashed TEXT NOT NULL,
    password_salted TEXT NOT NULL,
    password_peppered TEXT NOT NULL,
    password_salted_and_peppered TEXT NOT NULL
);
