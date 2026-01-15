SELECT
    id,
    name,
    mail
FROM
    passkey_users
WHERE
    id = $1;
