try:
  from os import path
  import sys
  from typing import Any, Union

  from bson.binary import STANDARD, UUID
  from bson.codec_options import CodecOptions
  from pymongo import MongoClient
  from pymongo.encryption import ClientEncryption
  from pymongo.errors import EncryptionError, ServerSelectionTimeoutError, ConnectionFailure, OperationFailure
except ImportError as e:
  from os import path
  print(f"Import error for {path.basename(__file__)}: {e}")
  exit(1)

class MDB:
  def __init__(
      self,
      connection_string: str,
      kms_provider_details: tuple[dict | None]=None,
      keyvault_namespace: tuple[str | None]=None,
      ca_file_path: tuple[str | None]=None,
      tls_key_cert_path: tuple[str | None]=None
    ) -> None:
    self.connection_string = connection_string
    self.kms_provider_details = kms_provider_details
    self.keyvault_namespace = keyvault_namespace
    self.ca_file_path = ca_file_path
    self.tls_key_cert_path = tls_key_cert_path
    self.__client_encryption = None
    self.__encrypted_client = None
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
      client = MongoClient(self.connection_string, auto_encryption_opts=auto_encryption_opts)
      client.admin.command('hello')
      return client, None
    except (ServerSelectionTimeoutError, ConnectionFailure, OperationFailure) as e:
      return None, f"Cannot connect to database, please check settings in config file: {e}"
  
  def __get_client_encryption(self) -> tuple[ClientEncryption | None, str | None]:
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
    tuple[ClientEncryption | None, str | None]: 
        - A tuple where the first element is a ClientEncryption object if successful, otherwise None.
        - The second element is None if successful, otherwise an error message indicating which file was not found.

    Note:
    This function verifies the existence of the provided CA file and TLS key certificate file before attempting to 
    instantiate the ClientEncryption object. If either of the files does not exist, an error message is returned.
    The ClientEncryption object is used to perform explicit encryption and decryption operations on data.
    """
    if self.ca_file_path and not path.isfile(self.ca_file_path):
      return None, f"{self.ca_file_path} does not exist"
    if self.tls_key_cert_path and not path.isfile(self.tls_key_cert_path):
      return None, f"{self.tls_key_cert_path} does not exist"
    client_encryption = ClientEncryption(
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
    return client_encryption, None
  
  def create_encrypted_client(self, auto_encryption_opts: dict) -> Union[str | None]:
    """
    Create and return an encrypted MongoDB client using the provided auto encryption options.

    Parameters:
    auto_encryption_opts (dict): A dictionary containing options for automatic encryption configuration.

    Returns:
    Union[str | None]:
        - None if the encrypted client is successfully created.
        - An error message (str) if the client creation fails.

    Note:
    This function creates an encrypted MongoDB client using the provided auto encryption options and assigns it to 
    the instance variable `__encrypted_client`. It calls the `__get_client` method with the connection string 
    and encryption options. If there is an error during client creation, the error message is stored in the `result`
    instance variable and None is returned.
    """
    self.__encrypted_client, err = self.__get_client(auto_encryption_opts)
    if err is not None:
      self.result = err
    return None


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

  def encrypted_insert_one(self, db, coll: str, document: dict) -> Any:
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
    try:
      result = self.__encrypted_client[db][coll].insert_one(document)
      return result
    except EncryptionError as e:
      raise e
  
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
  
  def encrypted_find_one(self, db, coll: str, document: dict) -> Any:
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
    try:
      result = self.__encrypted_client[db][coll].find_one(document)
      return result
    except EncryptionError as e:
      raise e
  
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
    # Create ClientEncryption object if not already existing
    if not self.__client_encryption:
      if self.kms_provider_details and self.keyvault_namespace:
        self.__client_encryption, err = self.__get_client_encryption()
        if err is not None:
          print(err)
          raise err
      else:
        print("`kms_provider_details` and/or `keyvault_namespace not provided")
        sys.exit(1)
    dek_uuid = self.__client_encryption.get_key_by_alt_name(dek_alt_name)
    if dek_uuid:
      return dek_uuid["_id"]
    return None
