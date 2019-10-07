from csv import reader
from app.util.hash import hash_pbkdf2, hash_sha256, random_salt
COMMON_PASSWORDS_PATH = 'common_passwords.txt'
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def load_common_passwords():
    with open(COMMON_PASSWORDS_PATH) as f:
        pws = list(reader(f))
    return pws

def brute_force_attack(target_hash, target_salt):
    pws = load_common_passwords()
    
    for pw in pws:

        guess = hash_pbkdf2(pw[0] ,target_salt)
        if guess == target_hash:
            print(pw)
            return pw
        

    

def main():
    salted_creds = load_breach(SALTED_BREACH_PATH)
    brute_force_attack(salted_creds[0][1], salted_creds[0][2])

if __name__ == "__main__":
    main()