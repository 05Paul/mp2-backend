SELECT
  credential
FROM 
  passkey_user_credentials
WHERE 
  user_id = $1;
