"""
This module provides functions required for database.
"""
from pymongo import MongoClient


CONNECTION_STRING = "mongodb://localhost:27017"
#mongodb adds the id for each object automatically using mongo's
USER_ACCOUNT_COLLECTION = "user-account"
#{"username":"","password":""}


def get_database():
    client = MongoClient(CONNECTION_STRING)
    return client["secure-messaging-app"]

dbname=get_database()

def insertOne(collectionName,item):
    collection=dbname[collectionName]
    return collection.insert_one(item)

def findAll(collectionName):
    collection=dbname[collectionName]
    return collection.find()

def findOne(collectionName,filter):
    collection=dbname[collectionName]
    return collection.find_one(filter)
def deleteOne(collectionName,filter):
    collection=dbname[collectionName]
    return collection.find_one_and_delete(filter)
