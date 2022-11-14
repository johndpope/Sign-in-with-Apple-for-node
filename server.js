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
/* INSTRUCTIONS - PREFACE
Create key - Sign in with Apple
https://developer.apple.com/account/resources/authkeys/list
Download p8 file from apple into /.static/
2) update name */
const keyFile = '.static/AuthKey_KFJ7FG3H2V.p8'
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
		"redirectURI": "https://qfwzdkpmyzajmmvupgzy.supabase.co/auth/v1/callback"
	},
	"supabase": {
		"jwtSecret": "gpmz/H4tuUkI5Tn67IalUkTwrk00Ue0NO2vpTDWhW3PQ0e28MlKJvJZvbhYtmiH0mBCQ0AnZ8nYNlqqUfgvlQQ=="
	}
}

const GOTRUE_URL = NEXT_PUBLIC_SUPABASE_URL;//'http://0.0.0.0:9999'
const goTrueClient = new GoTrueClient({ url: GOTRUE_URL })

// POSTGRES
const pool = new Pool({
	user: 'postgres',
	password: config.postgres.password,
	host: config.postgres.host,
	port: config.postgres.port,
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
		console.log("✅ Found User:", res.rows[0],"on email:",email);
		return res.rows[0];
	}catch(error){
		console.log("error:", error);
		return null;
	}
	
}

// TODO - correctly update the identies to align to production values 
// eg. SELECT * FROM identities;   //  should show apple
const createAccountManually = async (email) => {

	let user =  await findExistingUserByEmail(email);
	if (user == null){
		try{
			const res = await pool.query('INSERT INTO auth.users ( id, instance_id, ROLE, aud, email, raw_app_meta_data, raw_user_meta_data, is_super_admin, encrypted_password, created_at, updated_at, last_sign_in_at, email_confirmed_at, confirmation_sent_at, confirmation_token, recovery_token, email_change_token_new, email_change ) VALUES ( gen_random_uuid(), \'00000000-0000-0000-0000-000000000000\', \'authenticated\', \'authenticated\', $1, \'{"provider":"apple","providers":["apple"]}\', \'{}\', FALSE, \'password\', NOW(), NOW(), NOW(), NOW(), NOW(), \'\', \'\', \'\', \'\' ); ;', [email]);
			const res1 = await pool.query('SELECT id,email FROM auth.users WHERE email = $1::Text;', [email]);
			let result = res1.rows[0];
			console.log("result.id:", result.id);
			const res2 = await pool.query('INSERT INTO auth.identities ( id, provider, user_id, identity_data, last_sign_in_at, created_at, updated_at ) VALUES ( $1::UUID, \'email\', $1::UUID, json_build_object( \'sub\', $1::UUID ), NOW(), NOW(), NOW() );', [result.id]);
			
			console.log("res:", res.rows);
			console.log("res1:", res1.rows);
			return;
		}catch(error){
			console.log("error:", error);
			return null;
		}
	}else{
		return user;
	}
}

const returnExistingSupabaseJWTorCreateAccount = async (jwtClaims) => {

	let user =  await findExistingUserByEmail(jwtClaims.email);

	if (user == null) {
		let slimUserMeta =  {   email: jwtClaims.email,
			email_verified: true,
			full_name: 'John Pope',
			iss: 'https://appleid.apple.com/auth/keys',
			name: 'John Pope',
			provider_id: "what???",
			sub: jwtClaims.sub
		}
		console.log("🌱 creating user");
		const { data: data, error } = await supabase.auth.admin.createUser({
			email: jwtClaims.email,
			email_confirm: true, // missing provide / identities guff
			user_metadata:jwtClaims,
			app_metadata:{ provider: 'apple', providers: [ 'apple' ] }
		})


		let newUser = data.user;
		console.log("newUser:", newUser);
		{
			const { data: response, error } = await supabase.auth.admin.listUsers();
			// console.log("listUsers response:", response.users);
			for await (let u of response.users) {
				if (u.id == newUser.id) {
					console.log("we found existing gotrue user in supabase:", u);
					// console.log("issue jwt:", u.jwt());
				}
			}
		}

			

		// create an access token
		let claims = {
			"StandardClaims": {
				"sub": newUser.id,
				"aud": "",
				"exp": Math.floor(Date.now() / 1000),
			},
			"Email": newUser.Email,
			"AppMetaData": newUser.AppMetaData,
			"UserMetaData": newUser.UserMetaData,
		}
		console.log("✅ claims:", claims);
		const jwt = sign(claims, config.supabase.jwtSecret);
		console.log("jwt:", jwt);
		return jwt;
		
	} else {
		// Match up to the userId to user dictionary
		{
			const { data: response, error } = await supabase.auth.admin.listUsers();
			// console.log("listUsers response:", response.users);
			for await (let u of response.users) {
				if (u.id == user.id) {
					console.log("we found existing user in supabase:", u);
				}
			}
		}
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
		console.log("descrypt on https://jwt.io -", jwt);
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


// curl -X POST -d 'code=cf2add9a5a15842d4b06683fa89152446.0.ntrx.OHzVN63UPWqSjEr-oBsU6g' http://0.0.0.0:80/login/apple
app.post('/login/apple', bodyParser.urlencoded({ extended: false }), (req, res, next) => {
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
			console.log("🍭 apple jwtClaims:", jwtClaims);
			returnExistingSupabaseJWTorCreateAccount(jwtClaims).then((newUser) => {
				return res.status(200).json({
					message: 'ok',
					data: newUser
				})
			});
			
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
//app.listen(process.env.PORT || 3000, () => console.log(`App listening on port ${process.env.PORT || 3000}!  http://0.0.0.0:3000 callbackurl  http://0.0.0.0:3000/login/apple `))

const jwtClaims = {
	iss: 'https://appleid.apple.com',
	aud: 'app.test.ios',
	exp: 1579483805,
	iat: 1579483205,
	sub: '000317.c7d501c4f43c4a40ac3f79e122336fcf.0952',
	at_hash: 'G413OYB2Ai7UY5GtiuG68A',
	email: 'john.pope@wweevv.app',
	email_verified: 'true',
	is_private_email: 'true',
	auth_time: 1579483204
};
 returnExistingSupabaseJWTorCreateAccount(jwtClaims);

// console.log("json:", JSON.stringify(jwtClaims));
// createAccountManually("john.pope+1@wweevv.app")
