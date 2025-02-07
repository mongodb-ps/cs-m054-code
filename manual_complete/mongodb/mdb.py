try:
  from os import path
  from bson.binary import STANDARD, Binary, UUID
  from bson.codec_options import CodecOptions
  from enum import Enum
  from pymongo import MongoClient
  from pymongo.encryption import Algorithm
  from pymongo.encryption import ClientEncryption
  from pymongo.errors import EncryptionError, ServerSelectionTimeoutError, ConnectionFailure, OperationFailure
  from typing import Any
except ImportError as e:
  from os import path
  print(f"Import error for {path.basename(__file__)}: {e}")
  exit(1)

class ALG(Enum):
  RAND = 1
  DET = 2

class MDB:
  def __init__(
      self,
      connection_string: str,
      auto_encryption_opts: tuple[dict | None]=None,
      kms_provider: tuple[dict | None]=None,
      keyvault_namespace: tuple[str | None]=None,
      ca_file_path: tuple[str | None]=None,
      tls_key_cert_path: tuple[str | None]=None
    ) -> None:
    self.__client, err = self.__get_client(connection_string, auto_encryption_opts)
    if err is not None:
      self.result = err
    if kms_provider and keyvault_namespace:
      self.__client_encryption, err = self.__get_client_encryption(kms_provider, keyvault_namespace, ca_file_path, tls_key_cert_path)
      if err is not None:
        self.result = err


  def __get_client(self, connection_string: str, auto_encryption_opts: tuple[dict | None] = None) -> tuple[MongoClient | None, str | None]:
    """ Returns a MongoDB client instance

    Creates a  MongoDB client instance and tests the client via a `hello` to the server

    Parameters
    ------------
      connection_string: string
        MongoDB connection string URI containing username, password, host, port, tls, etc
    Return
    ------------
      client: mongo.MongoClient
        MongoDB client instance
      err: error
        Error message or None of successful
    """

    try:
      client = MongoClient(connection_string, auto_encryption_opts)
      client.admin.command('hello')
      return client, None
    except (ServerSelectionTimeoutError, ConnectionFailure, OperationFailure) as e:
      return None, f"Cannot connect to database, please check settings in config file: {e}"
  
  def __get_client_encryption(self, kms_provider: dict, keyvault_namespace: str, ca_file: str, tls_key_cert: str) -> tuple[ClientEncryption | None, str | None]:
    if ca_file and not path.isfile(ca_file):
      return None, f"{ca_file} does not exist"
    if tls_key_cert and not path.isfile(tls_key_cert):
      return None, f"{tls_key_cert} does not exist"
    client_encryption = ClientEncryption(
      kms_provider,
      keyvault_namespace,
      self.__client,
      CodecOptions(uuid_representation=STANDARD),
      kms_tls_options = {
        "kmip": {
          "tlsCAFile": ca_file,
          "tlsCertificateKeyFile": tls_key_cert
        }
      }
    )
    return client_encryption, None

  def decrypt_fields(self, data: dict) -> dict:
    """ Public method for taking an object and then decrypting fields that are encrypted

    Parameters
    -----------
      data: value
        A value to be tested, and decrypted if required

    Return
    -----------
      data/unencrypted_data: value    
    """
    return self.__traverse_bson(data)
  
  def encrypt_field(self, field_v: any, algorithm: ALG, dek: str) -> Binary:
    """ Public method for encrypting a field value

    Parameters
    -----------
      field_v: value
        A value to be encrypted
      algorithm: "RAND" or "DET"
      dek: UUID of the dek used to encrypt

    Return
    -----------
      encrypted data in Binary Subtype 6    
    """
    try:
      if algorithm == ALG.RAND:
        alg = Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random
      else:
        alg = Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic
      return self.__client_encryption.encrypt(field_v, alg, dek)
    except EncryptionError as e:
      raise e

  def decrypt_field(self, data):
    """ Returns a decrypted value if the input is encrypted, or returns the input value

    Tests the input value to determine if it is a BSON binary subtype 6 (aka encrypted data).
    If true, the value is decrypted. If false the input value is returned

    Parameters
    -----------
      data: value
        A value to be tested, and decrypted if required
    Return
    -----------
      data/unencrypted_data: value
        unencrypted or input value
    """

    try:
      if type(data) == Binary and data.subtype == 6:

        decrypted_data = self.__client_encryption.decrypt(data)

        return decrypted_data
      else:
        return data
    except EncryptionError as e:
      raise e

  def __traverse_bson(self, data: dict) -> dict | str:
    """ Iterates over a object/value and determines if the value is a scalar or document

    Tests the input value is a list or dictionary, if not calls the `decrypt_data` function, if
    true it calls itself with the value as the input. 

    Parameters
    -----------
      data: value
        A value to be tested, and decrypted if required
    Return
    -----------
      data/unencrypted_data: value
        unencrypted or input value
    """

    if isinstance(data, list):
      return [self.__traverse_bson(v) for v in data]
    elif isinstance(data, dict):
      return {k: self.__traverse_bson(v) for k, v in data.items()}
    else:
      return self.decrypt_field(data)
    
  def insert_one(self, db, coll: str, document: dict) -> Any:
    """ Insert a document

    Parameters
    -----------
      db: value
        Name of database
      coll: value
        Name of collection
      document: value
        insert document
    Return
    -----------
      Insert result: value
        Result of operation

    """
    return self.__client[db][coll].insert_one(document)
  
  def find_one(self, db, coll: str, document: dict) -> Any:
    """ Find a document

    Parameters
    -----------
      db: value
        Name of database
      coll: value
        Name of collection
      document: value
        query document
    Return
    -----------
      Insert result: value
        Result of operation

    """
    return self.__client[db][coll].find_one(document)
  
  def get_dek_uuid(self, dek_alt_name: str) -> tuple[UUID | None]:
    """ Get UUID of a DEK searched by Alternative name

    Parameters
    -----------
      dek_alt_name: value
        Alternate name of DEK
    Return
    -----------
      UUID or None

    """
    dek_uuid = self.__client_encryption.get_key_by_alt_name(dek_alt_name)
    if dek_uuid:
      return dek_uuid["_id"]
    return None
