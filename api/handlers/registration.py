from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
from ..conf import pepper  #pepper stored in configuration file
from ..conf import secret_key  #Secret Key stored in configuration file

from .base import BaseHandler

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            
            full_name = body.get('full_name', '')
            if not isinstance(full_name, str):
                raise Exception()
            
            d_fullName = full_name
            
            address = body.get('address', '')
            if not isinstance(address, str):
                raise Exception()
            
            date_of_birth = body.get('date_of_birth', '')
            if not isinstance(date_of_birth, str):
                raise Exception()
            phone_number = body.get('phone_number', '')
            if not isinstance(phone_number, str):
                raise Exception()
            list_of_disabilities = body.get('disabilities', '')
            if not isinstance(list_of_disabilities, str):
                raise Exception()
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        ########################################################################################
        salt = os.urandom(16)   # Generate a random salt

        # Hash the password using Scrypt
        kdf = Scrypt(
            salt = salt,
            length = 32,
            n = 2**14,
            r = 8,
            p = 1,
            backend = default_backend()
        )
        password_bytes = password.encode('utf-8')
        peppered_password = password_bytes + pepper # Append the pepper to the password
        hashed_password = kdf.derive(peppered_password)
        hashed_password_b64 = base64.b64encode(hashed_password).decode('utf-8')

        # Encrypt sensitive fields using AES-CBC
        def encrypt_field(field):
            if not field:
                return '', ''
            iv = os.urandom(16)   # 128-bit IV for AES-CBC
            padder = padding.PKCS7(128).padder()
            field_bytes = field.encode('utf-8')
            padded_data = padder.update(field_bytes) + padder.finalize()

            cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(iv).decode('utf-8')
        
        # Encrypt new fields
        full_name, full_name_iv = encrypt_field(full_name)
        address, address_iv = encrypt_field(address)
        date_of_birth, date_of_birth_iv = encrypt_field(date_of_birth)
        phone_number, phone_number_iv = encrypt_field(phone_number)
        disabilities, disabilities_iv = encrypt_field(list_of_disabilities)

        yield self.db.users.insert_one({
            'email': email,
            'password': hashed_password_b64,
            'salt': base64.b64encode(salt).decode('utf-8'),
            'displayName': display_name,
            'fullName': full_name,
            'fullNameIV': full_name_iv,
            'address': address,
            'addressIV': address_iv,
            'dateOfBirth': date_of_birth,
            'dateOfBirthIV': date_of_birth_iv,
            'phoneNumber': phone_number,
            'phoneNumberIV': phone_number_iv,
            'listOfDisabilities': disabilities,
            'listOfDisabilitiesIV': disabilities_iv
        })
        ######################################################################################

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()
