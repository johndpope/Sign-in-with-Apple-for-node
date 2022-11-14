const express = require('express')
const app = express()
const path = require('path')
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken');
const fs = require('fs')
const axios = require('axios')
const qs = require('qs');
const NodeRSA = require('node-rsa');
const TOKEN_ISSUER = 'https://appleid.apple.com';
const { createClient } = require('@supabase/supabase-js');
const { GoTrueClient } = require('@supabase/gotrue-js');
const sign = require('jwt-encode');
var Pool = require('pg-pool')

// by default the pool uses the same
// configuration as whatever `pg` version you have installed
require('dotenv').config({ path: '.env' });


const NEXT_PUBLIC_SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const POSTGRES_URL = process.env.POSTGRES_URL;
const POSTGRES_PWD = process.env.POSTGRES_PWD;


const NEXT_PUBLIC_SUPABASE_SERVICE_KEY = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_KEY;
if (!NEXT_PUBLIC_SUPABASE_URL)
	throw new Error('Missing env.NEXT_PUBLIC_SUPABASE_URL');
if (!NEXT_PUBLIC_SUPABASE_SERVICE_KEY)
	throw new Error('Missing env.NEXT_PUBLIC_SUPABASE_SERVICE_KEY');


const supabase = createClient(NEXT_PUBLIC_SUPABASE_URL, NEXT_PUBLIC_SUPABASE_SERVICE_KEY);

/// N.B. for docker local - jwSecret must match  GOTRUE_JWT_SECRET="1234" in .env.docker
const config = {
	"postgres": {
		"host": POSTGRES_URL,
		"port": 5432,
		"password":POSTGRES_PWD
	},
	"apple": {
		"clientID": "com.wweevv.client",
		"teamID": "PP83B8JPN5",
		"keyID": "KFJ7FG3H2V",
		"p8Filename": "AuthKey_KFJ7FG3H2V.p8",
		"redirectURI": "https:/www.wweevv.app/success"
	},
	"supabase": {
		"jwtSecret": "gpmz/H4tuUkI5Tn67IalUkTwrk00Ue0NO2vpTDWhW3PQ0e28MlKJvJZvbhYtmiH0mBCQ0AnZ8nYNlqqUfgvlQQ=="
	}
}

const GOTRUE_URL = NEXT_PUBLIC_SUPABASE_URL;//'http://0.0.0.0:9999'
const auth = new GoTrueClient({ url: GOTRUE_URL })

/* INSTRUCTIONS - PREFACE
Create key - Sign in with Apple
https://developer.apple.com/account/resources/authkeys/list
Download p8 file from apple into /.static/
2) update name */
const keyFile = '.static/AuthKey_KFJ7FG3H2V.p8'
/*
3) update clientID/teamID/keyID/p8Filename/redirectURI below
3) update credentials for postgres
*/

// POSTGRES
const pool = new Pool({
	user: 'postgres',
	password: 'aNBsCsO0D2AWO5jb',
	host: 'db.qfwzdkpmyzajmmvupgzy.supabase.co',
	port: 5432,
});


// BEGIN APPLE LOGIN 
// https://developer.apple.com/documentation/signinwithapplerestapi/generate_and_validate_tokens
//  const url = new URL(`https://appleid.apple.com/auth/authorize?scope=name%20email&client_id=${appleid.client_id}&redirect_uri=${redirectUri}&response_type=code%20id_token&response_mode=form_post`)

const getAuthorizationUrl = () => {
	const url = new URL('https://appleid.apple.com/auth/authorize');
	url.searchParams.append('response_type', 'code id_token');
	url.searchParams.append('response_mode', 'form_post');
	url.searchParams.append('client_id', config.apple.clientID);
	url.searchParams.append('redirect_uri', config.apple.redirectURI);
	url.searchParams.append('scope', 'name,email');
	return url.toString();
};


//   JWT client secret
const getClientSecret = () => {
	const privateKey = fs.readFileSync(keyFile, { encoding: "utf-8" });

	const headers = {
		alg: 'ES256',
		kid: config.apple.keyID,
	}
	const timeNow = Math.floor(Date.now() / 1000);
	let fiveMinutes = 5 * 60 * 1000;
	const claims = {
		iss: config.apple.teamID,
		aud: 'https://appleid.apple.com',
		sub: config.apple.clientID,
		iat: timeNow,
		exp: timeNow + fiveMinutes
	}

	token = jwt.sign(claims, privateKey, {
		algorithm: 'ES256',
		header: headers,
		// expiresIn: '24h'
	});
	return token
}

const getAppleIDPublicKey = async (kid) => {
	let res = await axios.request({
		method: "GET",
		url: "https://appleid.apple.com/auth/keys",
	})
	// console.log("res:",res)
	const keys = res.data.keys;
	const key = keys.find(k => k.kid === kid);

	const pubKey = new NodeRSA();
	pubKey.importKey({ n: Buffer.from(key.n, 'base64'), e: Buffer.from(key.e, 'base64') }, 'components-public');
	return pubKey.exportKey(['public']);
};

// ✅  WE HAVE SUCCESSFULLY LOGGED IN 
const findExistingUserByEmail = async (email) => {
	try{
		const res = await pool.query('SELECT id,email,encrypted_password FROM auth.users WHERE email = $1', [email]);
		if (res.rows.length == 0) {
			console.log("⚠️ No match on supabase for email:",email);
			return null;
		}
		console.log("ok:", res.rows[0]);
		return res.rows[0];
	}catch(error){
		console.log("error:", error);
		return null;
	}
	
}
const returnExistingSupabaseJWTorCreateAccount = async (jwtClaims) => {

	let user =  await findExistingUserByEmail(jwtClaims.email);
	{
		const { data: response, error } = await supabase.auth.admin.listUsers();
		// console.log("listUsers response:", response.users);
		for await (let u of response.users) {
			if (u.id == user.id) {
				console.log("we found existing user in supabase:", u);
			}
		}
	}

	if (user == null) {
		console.log("🌱 creating user");
		const { data: newUser, error } = await supabase.auth.admin.createUser({
			email: jwtClaims.email,
			email_confirm: true // missing provide / identities guff
		})
		console.log("newUser:", newUser);

	} else {
		console.log("🌱 we found a gotrue user:",user);
		// create an access token
		let claims = {
			"StandardClaims": {
				"sub": user.id,
				"aud": "",
				"exp": Math.floor(Date.now() / 1000),
			},
			"Email": user.Email,
			"AppMetaData": user.AppMetaData,
			"UserMetaData": user.UserMetaData,
		}
		console.log("✅ claims:", claims);
		const jwt = sign(claims, config.supabase.jwtSecret);
		console.log("jwt:", jwt);
		return jwt;
	}

}

// {"id":"9df2971d-fdf7-471a-b4ed-ccdab7f75f32",
// "aud":"",
// "role":"",
// "email":"test@test.com",
// "phone":"",
// "confirmation_sent_at":"2022-11-14T02:46:04.177563533Z",
// "app_metadata":{"provider":"email","providers":["email"]},
// "user_metadata":{},
// "identities":[{"id":"9df2971d-fdf7-471a-b4ed-ccdab7f75f32","user_id":"9df2971d-fdf7-471a-b4ed-ccdab7f75f32",
//        "identity_data":{"email":"test@test.com","sub":"9df2971d-fdf7-471a-b4ed-ccdab7f75f32"},
// 	   "provider":"email",
// 	   "last_sign_in_at":"2022-11-14T02:46:04.175077127Z",
// 	   "created_at":"2022-11-14T02:46:04.175145Z",
// 	   "updated_at":"2022-11-14T02:46:04.175147Z"}],
// "created_at":"2022-11-14T02:46:04.168506Z","updated_at":"2022-11-14T02:46:04.177712Z"}%


// make sure the apple login was for this app (and not just a successful login from other app)
const verifyIdToken = async (clientSecret, idToken, clientID) => {

	if (!idToken) {
		let error = new Error("OBJECT_NOT_FOUND", 'id token is invalid for this user.')
		console.error('ERROR_ACCOUNT_CREATION_FAILED');
		throw error;
	}
	let jwtClaims = {};
	try {
		const decodedToken = jwt.decode(idToken, { complete: true });
		const applePublicKey = await getAppleIDPublicKey(decodedToken.header.kid);
		jwtClaims = jwt.verify(idToken, applePublicKey, { algorithms: 'RS256' });
	} catch (err) {
		console.log('get apple public key', err);
		console.error('ERROR_ACCOUNT_CREATION_FAILED');
		console.error(err);
		throw new Error("publickey", 'apple public key is invalid for this user.');;
	}
	// verify token here - https://jwt.io/
	// console.log("clientSecret:",clientSecret) 
	// console.log("idToken:",idToken);    

	if (jwtClaims.iss !== TOKEN_ISSUER) {
		let error = new Error("OBJECT_NOT_FOUND", `id token not issued by correct OpenID provider - expected: ${TOKEN_ISSUER} | from: ${jwtClaims.iss}`)
		console.error('ERROR_ACCOUNT_CREATION_FAILED');
		throw error;
	}
	// if (jwtClaims.sub !== id) {
	//   throw new Error( "OBJECT_NOT_FOUND",`auth data is invalid for this user.`);
	// }
	if (clientID !== undefined && jwtClaims.aud !== clientID) {
		let error = new Error("OBJECT_NOT_FOUND", `jwt aud parameter does not include this client - is: ${jwtClaims.aud} | expected: ${config.apple.clientID}`)
		console.error('ERROR_ACCOUNT_CREATION_FAILED');
		throw error;
	}

	return jwtClaims;
};


//  curl -X POST -d 'code=cf2add9a5a15842d4b06683fa89152446.0.ntrx.OHzVN63UPWqSjEr-oBsU6g' http://0.0.0.0:80/login/apple
/*app.post('/login/apple', bodyParser.urlencoded({ extended: false }), (req, res, next) => {
	const clientSecret = getClientSecret();
	const params = {
		grant_type: 'authorization_code', // refresh_token authorization_code
		code: req.body.code,
		redirect_uri: config.apple.redirectURI,
		client_id: config.apple.clientID,
		client_secret: clientSecret,
		// refresh_token:req.body.id_token
	}
	axios({
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		data: qs.stringify(params),
		url: 'https://appleid.apple.com/auth/token'
	}).then(response => {
		verifyIdToken(clientSecret, response.data.id_token, config.apple.clientID).then((jwtClaims) => {
			return returnExistingSupabaseJWTorCreateAccount(jwtClaims);
		})
	}).catch(error => {
		console.log("error:", error);
		return res.status(500).json({
			message: 'error',
			error: error.response.data
		})
	})
})

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')))
app.listen(process.env.PORT || 80, () => console.log(`App listening on port ${process.env.PORT || 80}!  http://0.0.0.0:80/login/apple `))*/

const jwtClaims = {
	iss: 'https://appleid.apple.com',
	aud: 'app.test.ios',
	exp: 1579483805,
	iat: 1579483205,
	sub: '000317.c7d501c4f43c4a40ac3f79e122336fcf.0952',
	at_hash: 'G413OYB2Ai7UY5GtiuG68A',
	email: 'da6evzzywz@privaterelay.appleid.com',
	email_verified: 'true',
	is_private_email: 'true',
	auth_time: 1579483204
};
returnExistingSupabaseJWTorCreateAccount(jwtClaims);
