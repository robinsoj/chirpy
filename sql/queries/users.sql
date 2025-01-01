-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    now(),
    now(),
    $1,
    $2
)
RETURNING *;

-- name: DeleteUsers :exec
delete from users;

-- name: GetUserPassword :one
select id, created_at, updated_at, email, hashed_password, is_chirpy_red
from users
where email = $1
limit 1;

-- name: UpdateUserPassword :one
update users
set hashed_password = $1, updated_at = now(), email = $2
where id = $3
returning id, created_at, updated_at, email, is_chirpy_red;

-- name: UpgradeToRed :one
update users
set is_chirpy_red = true
where id = $1
returning id, created_at, updated_at, email, is_chirpy_red;