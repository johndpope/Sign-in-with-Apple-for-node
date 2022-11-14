require 'jwt'

key_file = '.static/AuthKey_***.p8'
team_id = '****'
client_id = '****' # CRITICAL - THIS IS NOT APP ID -> SELECT SERVICE ID (where it says APP ID) > CREATE + !!!! https://developer.apple.com/account/resources/identifiers/serviceId/  https://developer.apple.com/forums/thread/122536 
key_id = '****'

ecdsa_key = OpenSSL::PKey::EC.new IO.read key_file
# puts ecdsa_key
headers = {
  'kid' => key_id
}

claims = {
	'iss' => team_id,
	'iat' => Time.now.to_i,
	'exp' => Time.now.to_i + 86400*180,
	'aud' => 'https://appleid.apple.com',
	'sub' => client_id,
}

token = JWT.encode claims, ecdsa_key, 'ES256', headers

puts token


# https://app.supabase.com/project/ Authentication > Providers > Apple
# once you have this token add the corresponding SERVICE ID + this token