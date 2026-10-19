class User:
    def __init__(self, name=None, email=None, is_admin=False):
        self.name = name
        self.email = email
        self.is_admin = is_admin


class Order:
    query = None
