PORT = 4000

MONGODB_HOST = {
    'host': 'localhost',
    'port': 27017
}

MONGODB_DBNAME = 'cyberStudentsTest'

WORKERS = 1

# AES-256 encryption key (Base64 encoded)
import base64
import os

pepper = base64.b64decode("Q2Fycm90VGhpc0lzU2VjdXJlQmVjYXVzZUl0c0xvbmc=")
secret_key = base64.b64decode("kUfLNs9a1h2dOVsbn0wEfkK1dsBzLKR4eTabpb0F7b4=")