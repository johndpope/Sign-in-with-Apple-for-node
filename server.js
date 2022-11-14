
const express = require('express')
const app = express()
const path = require('path')
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken');
const fs = require('fs')
const axios = require('axios')
const qs = require('qs');
const NodeRSA = require('node-rsa');
const pg = require('pg');
const TOKEN_ISSUER = 'https://appleid.apple.com';
// const passport = require('passport');

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
// node-pg returns numerics as strings by default. since we don't expect to
// have large currency values, we'll parse them as floats instead.
pg.types.setTypeParser(1700, (val) => parseFloat(val));

const db = new pg.Pool({
	max: 10,
	min: 2,
	idleTimeoutMillis: 1000, // close idle clients after 1 second
	connectionTimeoutMillis: 1000, // return an error after 1 second if connection could not be established
	database: 'postgres',
	user: 'postgres',
	// Gotrue docker
	host: '0.0.0.0',
	port: 5432,
	password: 'root',
});

const config = {
  "apple" : {
    "clientID": "com.wweevv.client",
    "teamID": "PP83B8JPN5",
    "keyID": "KFJ7FG3H2V",
    "p8Filename": "AuthKey_KFJ7FG3H2V.p8",
    "redirectURI": "https:/www.wweevv.app/success"
  }
}


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
const returnExistingSupabaseJWTorCreateAccount = async (claims) => {
			// ASSUME EVERY EMAIL IS VERIFIED
			const jwtClaims = { iss: 'https://appleid.apple.com',
			  aud: 'app.test.ios', 
			  exp: 1579483805,
			  iat: 1579483205,
			  sub: '000317.c7d501c4f43c4a40ac3f79e122336fcf.0952',
			  at_hash: 'G413OYB2Ai7UY5GtiuG68A',
			  email: 'da6evzzywz@privaterelay.appleid.com',
			  email_verified: 'true',
			  is_private_email: 'true',
			  auth_time: 1579483204 }


	const res = await db.query('SELECT * FROM auth.users WHERE email = $1', ["test@test.com"]);
	console.log("ok:",res.rows[0].id);


	
			// TODO - 
			// IF EXISTING APPLE ID) WHERE the email = matches
			//  - check it's enabled
			//  - return valid JWT
			// {"provider":"apple","providers":["apple"]}
			// ELSE) create new account
      

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


// make sure the apple login was for this app
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

/*
//  curl -X POST -d 'code=cf2add9a5a15842d4b06683fa89152446.0.ntrx.OHzVN63UPWqSjEr-oBsU6g' http://0.0.0.0:80/login/apple
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
app.listen(process.env.PORT || 80, () => console.log(`App listening on port ${process.env.PORT || 80}!  http://0.0.0.0:80/login/apple `))
*/
returnExistingSupabaseJWTorCreateAccount();