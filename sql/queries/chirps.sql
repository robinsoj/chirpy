-- name: CreateChirp :one
insert into chirps (id, created_at, updated_at, body, user_id) values (
	gen_random_uuid(),
	now(),
	now(),
	$1,
	$2
)
returning *;

-- name: GetChirpsAsc :many
select *
from chirps
order by created_at asc;

-- name: GetChirpsDesc :many
select *
from chirps
order by created_at desc;

-- name: GetSingleChirp :one
select *
from chirps
where id = $1;

-- name: DeleteSingleChirp :one
delete from chirps
where user_id = $1 and id = $2
returning *;

-- name: GetChirpsByAuthorAsc :many
select *
from chirps
where user_id = $1
order by created_at asc;

-- name: GetChirpsByAuthorDesc :many
select *
from chirps
where user_id = $1
order by created_at desc;