https://github.com/supabase/gotrue

curl -X POST -d '{"email":"test@test.com","password":"test1234"}' https://[SERVER].supabase.co/auth/v1/signup -H "apikey: SERVICE_KEY" \
-H "Authorization: Bearer SERVICE_KEY"


curl -X POST -d '{"type":"recovery","password":"test1234"}' https://qfwzdkpmyzajmmvupgzy.supabase.co/auth/v1/verify
-H "apikey: SERVICE_TOKEN" \
-H "Authorization: Bearer SERVICE_TOKEN"


curl -X POST -d '{"type":"magiclink","email":"john.pope+19@wweevv.app"}' https://qfwzdkpmyzajmmvupgzy.supabase.co/auth/v1/admin/generate_link -H "apikey: SERVICE_TOKEN" \
-H "Authorization: Bearer SERVICE_TOKEN"




1 - invite
curl -X POST -d '{"email":"bob2+2@bob.com"}' https://qfwzdkpmyzajmmvupgzy.supabase.co/auth/v1/invite -H "apikey: SERVICE_TOKEN" \
-H "Authorization: Bearer SERVICE_TOKEN"



2 - verify

curl -X "POST" "https://qfwzdkpmyzajmmvupgzy.supabase.co/auth/v1/token?grant_type=id_token" \
    -H "apikey: SERVICE_TOKEN" \
     -H 'Content-Type: application/json; charset=utf-8' \
     -d '{
              "client_id": "com.wweevv.client",
              "nonce": "ed9844ef38be608d1df64953a13027e3a8be084f4dd9d80bf3368d06dfeba915",
              "id_token": "eyJraWQiOiJXNldjT0tCIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLnd3ZWV2di5jbGllbnQiLCJleHAiOjE2Njg1NjQwNjIsImlhdCI6MTY2ODQ3NzY2Miwic3ViIjoiMDAwMjY1LmM3MjMyYjU2MDE0YjQ0MzdhZGVjNTEzNzBiM2Q3MDA0LjE0MjIiLCJub25jZSI6ImVkOTg0NGVmMzhiZTYwOGQxZGY2NDk1M2ExMzAyN2UzYThiZTA4NGY0ZGQ5ZDgwYmYzMzY4ZDA2ZGZlYmE5MTUiLCJjX2hhc2giOiJnVllpV0ZqRzdHNEE4eFdLX3Zfd2RnIiwiZW1haWwiOiJ5cDR5c2Nxc2Z0QHByaXZhdGVyZWxheS5hcHBsZWlkLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSIsImlzX3ByaXZhdGVfZW1haWwiOiJ0cnVlIiwiYXV0aF90aW1lIjoxNjY4NDc3NjYyLCJub25jZV9zdXBwb3J0ZWQiOnRydWV9.vY-pKrb1Z0_8aWxy-_K1VySUtov3oeQB0f0Sqb3Vs8fswl22Iy7r9beqnAUbfeoHP9HJtDk3zRrwOP42MSSHW7njsYSN0v_YgJmc9wnBDSx7k8UgMcMG9LrLsTlhWFg-3_t1F46Vb-itBo39qkp6cmyPLeROo3O03V8mwWCKmrD6jlZswuZPxkuHCZ3MUPJOSwVFrt-MOxxoH6VbFBU4AOB31TvKqUxPYYUMe9dYIteipVfIhQL9TbY2zTvJSQcfdKThSC7APNYqqDw9VCJ9syLJt5LiUvqLjqJLqOaUQNLRwppwFJpBxbdD0y-PckZpvpR_N6LSE8aLTDi9nny3-Q",
              "issuer": "https://appleid.apple.com/"
      }'
