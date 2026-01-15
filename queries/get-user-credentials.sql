SELECT
    id,
    name,
    email,
    password_plain,
    password_hashed,
    password_salted,
    password_peppered,
    password_salted_and_peppered
FROM accounts
LIMIT $1
OFFSET $2
