SELECT
    id,
    name,
    mail
FROM
    passkey_users
WHERE
    mail = $1;
