# Sign-in-with-Apple-for-node -  hosted on your own ec2 server for supabase / mobile


## Run Gotrue Docker locally 
```shell
# FOR LOCAL POSTGRES DEV
git clone  https://github.com/supabase/gotrue/
cd gotrue
# FIX THE docker-compose-dev.yaml -> docker-compose.yaml
cp docker-compose-dev.yaml docker-compose.yaml
cp example.docker.env .env.docker
docker compose up
```

## VERIFY / CREATE USER (you need to do this on empty database - otherwise there's no user table)
## (this will also create the necessary tables to select from)
```shell
 curl -X POST -d '{"email":"test@test.com","password":"test1234"}' http://0.0.0.0:9999/signup
```
```javascript
{"id":"9df2971d-fdf7-471a-b4ed-ccdab7f75f32","aud":"","role":"","email":"test@test.com","phone":"","confirmation_sent_at":"2022-11-14T02:46:04.177563533Z","app_metadata":{"provider":"email","providers":["email"]},"user_metadata":{},"identities":[{"id":"9df2971d-fdf7-471a-b4ed-ccdab7f75f32","user_id":"9df2971d-fdf7-471a-b4ed-ccdab7f75f32","identity_data":{"email":"test@test.com","sub":"9df2971d-fdf7-471a-b4ed-ccdab7f75f32"},"provider":"email","last_sign_in_at":"2022-11-14T02:46:04.175077127Z","created_at":"2022-11-14T02:46:04.175145Z","updated_at":"2022-11-14T02:46:04.175147Z"}],"created_at":"2022-11-14T02:46:04.168506Z","updated_at":"2022-11-14T02:46:04.177712Z"}%
```


```shell
curl -X POST -d '{"email":"test@test.com","password":"test1234"}' https://[SERVER].supabase.co/auth/v1/signup -H "apikey: SERVICE_KEY" \
-H "Authorization: Bearer SERVICE_KEY"
```
```javascript
{"id":"cb8faa60-1222-4fe1-856f-a4610a78fbe7","aud":"authenticated","role":"authenticated","email":"test@test.com","phone":"","confirmation_sent_at":"2022-11-14T09:38:37.301763688Z","app_metadata":{"provider":"email","providers":["email"]},"user_metadata":{},"identities":[{"id":"cb8faa60-1222-4fe1-856f-a4610a78fbe7","user_id":"cb8faa60-1222-4fe1-856f-a4610a78fbe7","identity_data":{"sub":"cb8faa60-1222-4fe1-856f-a4610a78fbe7"},"provider":"email","last_sign_in_at":"2022-11-14T09:38:37.296324593Z","created_at":"2022-11-14T09:38:37.29638Z","updated_at":"2022-11-14T09:38:37.296384Z"}],"created_at":"2022-11-14T09:38:37.285201Z","updated_at":"2022-11-14T09:38:38.105364Z"}%
```


![VSCode](postgres1.png)
![VSCode](postgres.png)

```shell
git clone https://github.com/johndpope/Sign-in-with-Apple-for-node.git
cd Sign-in-with-Apple-for-node
# FOLLOW INSTRUCTIONS in server.js
# UPDATE .env with NEXT_PUBLIC_SUPABASE_URL
cp sample.env .env
npm install
npm run start
# open url
127.0.0.1



```
## Verify apple signup with iphone - pass the apple auth code here to create account on supabase
```shell
 curl -X POST -d 'code=cf2add9a5a15842d4b06683fa89152446.0.ntrx.OHzVN63UPWqSjEr-oBsU6g' http://0.0.0.0:80/login/apple

```
