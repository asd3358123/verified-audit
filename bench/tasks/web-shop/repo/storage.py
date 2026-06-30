import os

BASE = "/var/www/uploads"


def read_upload(filename):
    path = os.path.join(BASE, filename)
    with open(path) as f:
        return f.read()
