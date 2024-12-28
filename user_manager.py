"""
This module provides functions required for managing user accounts.
"""
import database as db
from pyargon2 import hash

CONST_SALT = "23LUCKY55;-)"
def hashPassword(username, password):
    # salt is combination of CONST_SALT and username 
    # salt must be unique and >= 8 in length
    salt = CONST_SALT + username    
    return hash(password, salt)

"""Create a new user account."""
def createAccount(username, password):
    if(db.findOne(db.USER_ACCOUNT_COLLECTION, {"username": username})):
        return "username-exist"
    else:
        hashed_password = hashPassword(username, password)
        user = {"username": username, "password": hashed_password}
        db.insertOne(db.USER_ACCOUNT_COLLECTION, user)
        return "signup-success"

def loginUser(username, password, ip):
    user = db.findOne(db.USER_ACCOUNT_COLLECTION, {"username": username})
    if(user):
        if(user["password"] != hashPassword(username,password)):
            return "login-wrong-credentials"
        else:
            return "login-success"
    else: 
        return "login-account-not-exist"
