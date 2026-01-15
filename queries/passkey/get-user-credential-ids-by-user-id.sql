SELECT
    credential_id
FROM
    passkey_user_credentials
WHERE
    user_id = $1;
