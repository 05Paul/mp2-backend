CREATE TABLE IF NOT EXISTS passkey_user_credentials(
	credential_id BYTEA PRIMARY KEY,
	user_id UUID references passkey_users(id) NOT NULL,
	credential JSONB NOT NULL
);
