from pymongo import MongoClient

class MongoSingleton:
    instance = None

    @classmethod
    def __new__(cls, *args, **kwargs):
        if cls.instance is None:
            cls.instance = super().__new__(*args, **kwargs)
        return cls.instance

    def __init__(self):
        self.client = MongoClient()
        self.db = self.client['login']


class MongoStorage:

    def __init__(self):
        self.mongo = MongoSingleton()

    def store_one(self, data, collection, *args):
        collection = getattr(self.mongo.db, collection)
        collection.insert_one(data)

    def load(self, collection_name, filter_name=None):
        collection = self.mongo.db[collection_name]
        if filter_name is not None:
            data = collection.find(filter_name)
        else:
            data = collection.find()
        return data

