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

// TODO - introspect apple for full_name / name - it's not initially returned...
const returnExistingSupabaseJWTorCreateAccount = async (jwtClaims,fullName,identityToken,nonce,givenName) => {

	// https://github.com/supabase/gotrue-js/pull/207 - looks like this approach is obsolete??
/*	let params =     {
		"client_id": "com.wweevv.client",
		"nonce": nonce,
		"id_token": identityToken,
		"issuer": "https://appleid.apple.com/"
	}       

	// BROKEN - obsolete method?
	const { user, session, error } = await supabase.auth.signIn({ //supabase.auth.signIn is not a function
        "oidc":{
            "id_token": identityToken,
            "nonce": nonce,
            "provider": 'apple'
        }
      })
	  console.log("user:",user);
	  console.log("session:",session);
	  console.log("🔥 error:",error);
	  
	// returns error {"code":500,"msg":"Internal server error","error_id":"35106675-66a4-417b-b045-5fc7410144ab"}%
	axios({ 
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded',
					'apikey':NEXT_PUBLIC_SUPABASE_SERVICE_KEY
		},
		data: qs.stringify(params),
		url: 'https://qfwzdkpmyzajmmvupgzy.supabase.co/auth/v1/token?grant_type=id_token'
	}).then(response => {
		console.log("response:",response);
	}).catch(error => {
		console.log("🔥 error:", error);
		// return res.status(500).json({
		// 	message: 'error',
		// 	error: error.response.data
		// })
	})
*/

	let user =  await findExistingUserByEmail(jwtClaims.email);

	if (user == null) {

		// CREATE THE USER
		let slimUserMeta =  {   email: jwtClaims.email,
			email_verified: true,
			full_name: fullName,
			iss: 'https://appleid.apple.com/auth/keys',
			name: givenName,
			provider_id: jwtClaims,
			sub: jwtClaims.sub
		}
		console.log("🌱 creating user");
		const { data: data, error } = await supabase.auth.admin.createUser({
			email: jwtClaims.email,
			email_confirm: true, // missing provide / identities guff
			user_metadata:slimUserMeta,
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

		// generate an access token - and return 
		var claims = newUser;
		claims.session_id = "12341234" // ??? 
		console.log("✅ claims:", claims);
		const jwt = sign(claims, config.supabase.jwtSecret);
		console.log("jwt:", jwt);

		{
			// test the access_token.
			const { data: response, error } = await supabase.auth.setAuth(jwt);
		}
		
		return jwt
		
	} else {

		console.log("🌱 we found a gotrue user:",user);
		// WE NEED TO GENERATE ACCESS-TOKEN somehow.

		// 1. approach - use the generate_link - https://github.com/supabase/gotrue#post-admingenerate_link
		//	
		// curl -X POST -d '{"type":"magiclink","email":"john.pope+19@wweevv.app"}' https://qfwzdkpmyzajmmvupgzy.supabase.co/auth/v1/admin/generate_link -H "apikey: SERVICE_KEY" -H "Authorization: Bearer SERVICE_KEY"
		//  this creates a cookie on the web browser / client side once you click through the 
		// {"id":"ac27f663-96f5-467f-9482-91287eb3e23e","aud":"authenticated","role":"authenticated","email":"john.pope+19@wweevv.app","phone":"","confirmation_sent_at":"2022-11-15T00:23:58.007313Z","recovery_sent_at":"2022-11-15T02:22:25.904989565Z","app_metadata":{"provider":"email","providers":["email"]},"user_metadata":{},"identities":[{"id":"ac27f663-96f5-467f-9482-91287eb3e23e","user_id":"ac27f663-96f5-467f-9482-91287eb3e23e","identity_data":{"sub":"ac27f663-96f5-467f-9482-91287eb3e23e"},"provider":"email","last_sign_in_at":"2022-11-15T00:23:58.101605Z","created_at":"2022-11-15T00:23:58.101655Z","updated_at":"2022-11-15T00:23:58.101658Z"}],"created_at":"2022-11-15T00:23:58.099149Z","updated_at":"2022-11-15T02:22:25.906115Z","action_link":"https://qfwzdkpmyzajmmvupgzy.supabase.co/auth/v1/verify?token=aba1467a3f5d4ec87e887ba1a671aec51337096f8f18dbfefd172400\u0026type=magiclink\u0026redirect_to=http://localhost:3000","email_otp":"479166","hashed_token":"aba1467a3f5d4ec87e887ba1a671aec51337096f8f18dbfefd172400","verification_type":"magiclink","redirect_to":"http://localhost:3000"}%
		// when I click through action-link - "action_link":"https://qfwzdkpmyzajmmvupgzy.supabase.co/auth/v1/verify?token=aba1467a3f5d4ec87e887ba1a671aec51337096f8f18dbfefd172400\u0026type=magiclink\u0026redirect_to=http://localhost:3000"
		// it successfully generates sb-access-token in client side cookie - but I need that value here to send to app.
		// It's possible we could use superagent here to achieve this - there's got to be a better way....

		// 2. find the user - invoke jwt() on it to get jwt. Unfortunately doesn't work.
		// Match up to the userId to user dictionary
		// {
		// 	const { data: response, error } = await supabase.auth.admin.listUsers();
		// 	// console.log("listUsers response:", response.users);
		// 	for await (let u of response.users) {
		// 		if (u.id == user.id) {
		// 			console.log("we found existing user in supabase:", u);
		// 		}
		// 	}
		// }

		// WHY ??? 
		{
			// const { data: tokenResponse, error } = await supabase.auth.token({
			// 	"email": "yp4yscqsft@privaterelay.appleid.com",
			// 	"password": ""
			//   })
			// console.log("tokenResponse:",tokenResponse);
		}

	
		// 3. craft an access token manually.
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
		console.log("decrypt on https://jwt.io -", jwt);
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
	let fullname = req.body.full_name;
	let email = req.body.email;
	let givenName = req.body.given_name;
	let identityToken = req.body.identity_token;
	let nonce = req.body.nonce;
	console.log("🍭 req.body:", req.body);


	const params = {
		grant_type: 'authorization_code', // id_token refresh_token authorization_code
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
			returnExistingSupabaseJWTorCreateAccount(jwtClaims,fullname,identityToken,nonce,givenName).then((userJwt) => {
				return res.status(200).json({
					message: 'ok',
					'sb_access_token' : userJwt,
					'sb_refresh_token': 'unknown'
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
app.listen(process.env.PORT || 3000, () => console.log(`App listening on port ${process.env.PORT || 3000}!  http://0.0.0.0:3000 callbackurl  http://0.0.0.0:3000/login/apple `))

