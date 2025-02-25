try:
  from os import path
  import sys
  from enum import Enum
  from typing import Any, Union

  from bson.binary import STANDARD, Binary, UUID
  from bson.codec_options import CodecOptions
  from pymongo import MongoClient
  from pymongo.encryption import Algorithm
  from pymongo.encryption import ClientEncryption
  from pymongo.errors import EncryptionError, ServerSelectionTimeoutError, ConnectionFailure, OperationFailure
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
      kms_name: Union[str, None],
      kms_provider_details: tuple[dict | None]=None,
      keyvault_namespace: tuple[str | None]=None,
      ca_file_path: tuple[str | None]=None,
      tls_key_cert_path: tuple[str | None]=None
    ) -> None:
    self.connection_string = connection_string
    self.kms_name = kms_name
    self.kms_provider_details = kms_provider_details
    self.keyvault_namespace = keyvault_namespace
    self.ca_file_path = ca_file_path
    self.tls_key_cert_path = tls_key_cert_path
    self.__client_encryption = None
    self.__client, err = self.__get_client()
    if err is not None:
      self.result = err

  def __get_client(self, auto_encryption_opts: tuple[dict | None] = None) -> tuple[MongoClient | None, str | None]:
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
      if auto_encryption_opts is not None:
        client = MongoClient(self.connection_string, auto_encryption_opts=auto_encryption_opts)
      else:
        client = MongoClient(self.connection_string)
      client.admin.command('hello')
      return client, None
    except (ServerSelectionTimeoutError, ConnectionFailure, OperationFailure) as e:
      return None, f"Cannot connect to database, please check settings in config file: {e}"
  
  def create_client_encryption(self) -> Union[str, None]:
    """ Create a ClientEncryption object for MongoDB client-side field level encryption, or return an error message if 
    the provided CA file or TLS key certificate file does not exist.

    Parameters from class
    ------------
    kms_provider_details (dict): A dictionary containing KMS (Key Management Service) provider details.
    keyvault_namespace (str): The namespace (database.collection) used for storing the encryption keys in the key vault.
    ca_file (str): Path to the Certificate Authority (CA) file for validating the KMS server.
    tls_key_cert (str): Path to the TLS certificate and private key file for authenticating the client to the KMS server.

    Returns
    ------------
    Union[str, None]: 
        - None if successful, otherwise an error message indicating which file was not found.

    Note:
    This function verifies the existence of the provided CA file and TLS key certificate file before attempting to 
    instantiate the ClientEncryption object. If either of the files does not exist, an error message is returned.
    The ClientEncryption object is used to perform explicit encryption and decryption operations on data.
    """
    if self.ca_file_path and not path.isfile(self.ca_file_path):
      return f"{self.ca_file_path} does not exist"
    if self.tls_key_cert_path and not path.isfile(self.tls_key_cert_path):
      return f"{self.tls_key_cert_path} does not exist"
    try:
      self.__client_encryption = ClientEncryption(
        self.kms_provider_details,
        self.keyvault_namespace,
        self.__client,
        CodecOptions(uuid_representation=STANDARD),
        kms_tls_options = {
          "kmip": {
            "tlsCAFile": self.ca_file_path,
            "tlsCertificateKeyFile": self.tls_key_cert_path
          }
        }
      )
    except ValueError as e:
      return e
    return None

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
      # Check the ClientEncryption object exists
      if not self.__client_encryption:
        raise f"ClientEncryption object is not instantiated"
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
      # Check the ClientEncryption object exists
      if not self.__client_encryption:
        raise f"ClientEncryption object is not instantiated"
      # Test to determine if fireld is encrypted, if so, decrypt data
      if type(data) == Binary and data.subtype == 6:

        decrypted_data = self.__client_encryption.<UPDATE_HERE> # perform the decryption of single values

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
    # Check the ClientEncryption object exists
    if not self.__client_encryption:
      raise f"ClientEncryption object is not instantiated"
    dek_uuid = self.__client_encryption.get_key_by_alt_name(dek_alt_name)
    if dek_uuid:
      return dek_uuid["_id"]
    return None
