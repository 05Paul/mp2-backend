INSERT INTO accounts(
    name,
    email,
    password_plain,
    password_hashed,
    password_salted,
    password_peppered,
    password_salted_and_peppered
)VALUES(
$1,
$2,
$3,
$4,
$5,
$6,
$7
) RETURNING id
