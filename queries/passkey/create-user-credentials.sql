INSERT INTO passkey_user_credentials(
	credential_id,
	user_id,
	credential
)
VALUES (
	$1,
	$2,
	$3
);
