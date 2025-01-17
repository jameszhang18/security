from csv import reader

from app.models.user import create_user

REGISTRATION_PATH = "app/scripts/registration.csv"

def register_users(db):
    create_user(db, "attacker", "attacker")
    create_user(db, "victim", "victim")
    create_user(db, "my", "my")
    with open(REGISTRATION_PATH) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        for creds in r:
            create_user(db, creds[0], creds[1])

