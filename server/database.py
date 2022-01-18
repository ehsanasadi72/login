from pymongo import MongoClient


class MongoSingleton:
    instance = {}

    @classmethod
    def __call__(cls, *args, **kwargs):
        if cls.instance is None:
            cls.instance = super().__new__(*args, **kwargs)
        return cls.instance

    def __init__(self):
        self.client = MongoClient()
        self.db = self.client['login']


class MongoConnection(MongoSingleton):

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.close()


class MongoStorage(MongoSingleton):

    def store_one(self, data, collection, *args):
        """
        store the data in collection
        :param data:
        :param collection:
        :param args:
        :return:
        """
        collection = getattr(self.db, collection)
        collection.insert_one(data)

    def load_one(self, collection_name, filter_name=None):
        """
        load the first data from database that matches the filter_name
        :param collection_name:name of collection
        :param filter_name:should write filter for what
         to return from database
        :return:
        """
        collection = self.db[collection_name]
        if filter_name is not None:
            data = collection.find_one(filter_name)
        else:
            data = collection.find_one()
        return data
