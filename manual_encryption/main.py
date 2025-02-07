try:
  from os import path
  from sys import version_info
  from bson.binary import STANDARD, Binary
  from bson.codec_options import CodecOptions
  from datetime import datetime
  from pymongo import MongoClient
  from pymongo.encryption import Algorithm
  from pymongo.encryption import ClientEncryption
  from pymongo.errors import EncryptionError, ServerSelectionTimeoutError, ConnectionFailure
  from urllib.parse import quote_plus
  import sys
except ImportError as e:
  print(f"Import error for {path.basename(__file__)}: {e}")
  exit(1)



# PUT VALUES HERE!
MDB_PASSWORD = <UPDATE_HERE> 
APP_USER = "app_user"
CA_PATH = "/data/pki/ca.pem"

def check_python_version() -> str | None:
  """Checks if the current Python version is supported.

  Returns:
    A string indicating that the current Python version is not supported, or None if the current Python version is supported.
  """
  if version_info.major < 3 or (version_info.major == 3 and version_info.minor < 10):
    return f"Python version {version_info.major}.{version_info.minor} is not supported, please use 3.10 or higher"
  return None

def mdb_client(connection_string: str) -> tuple[MongoClient | None, str | None]:
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
    client = MongoClient(connection_string)
    client.admin.command('hello')
    return client, None
  except (ServerSelectionTimeoutError, ConnectionFailure) as e:
    return None, f"Cannot connect to database, please check settings in config file: {e}"

def main():

  # check version of Python is correct
  err = check_python_version()
  if err is not None:
    print(err)
    exit(1)

  # Obviously this should not be hardcoded
  connection_string = "mongodb://%s:%s@mongodb-0:27017/?serverSelectionTimeoutMS=5000&tls=true&tlsCAFile=%s" % (
    quote_plus(APP_USER),
    quote_plus(MDB_PASSWORD),
    quote_plus(CA_PATH)
  )

  # Declare or key vault namespce
  keyvault_db = "__encryption"
  keyvault_coll = "__keyVault"
  keyvault_namespace = f"{keyvault_db}.{keyvault_coll}"

  # declare our key provider type
  provider = "kmip"

  # declare our key provider attributes
  kms_provider = {
    provider: {
      "endpoint": <UPDATE_HERE>
    }
  }
  
  # declare our database and collection
  encrypted_db_name = "companyData"
  encrypted_coll_name = "employee"

  # instantiate our MongoDB Client object
  client, err = mdb_client(connection_string)
  if err is not None:
    print(err)
    sys.exit(1)


  # Instantiate our ClientEncryption object
  client_encryption = ClientEncryption(
    kms_provider,
    keyvault_namespace,
    client,
    CodecOptions(uuid_representation=STANDARD),
    kms_tls_options = {
      "kmip": {
        "tlsCAFile": "/data/pki/ca.pem",
        "tlsCertificateKeyFile": "/data/pki/client-0.pem"
      }
    }
  )

  payload = {
    "name": {
      "firstName": "Manish",
      "lastName": "Engineer",
      "otherNames": None,
    },
    "address": {
      "streetAddress": "1 Bson Street",
      "suburbCounty": "Mongoville",
      "stateProvince": "Victoria",
      "zipPostcode": "3999",
      "country": "Oz"
    },
    "dob": datetime(1980, 10, 10),
    "phoneNumber": "1800MONGO",
    "salary": 999999.99,
    "taxIdentifier": "78SD20NN001",
    "role": [
      "CTO"
    ]
  }

  try:

    # retrieve the DEK UUID
    data_key_id_1 = <UPDATE_HERE> # Put code here to find the _id of the DEK we created previously using the "get_key_by_alt_name" method
    if data_key_id_1 is None:
      print("Failed to find DEK")
      sys.exit()

    # WRITE CODE HERE TO ENCRYPT THE APPROPRIATE FIELDS
    # Don't forget to handle to event of name.otherNames being null

    # Do deterministic fields
    payload["name"]["firstName"] = <UPDATE_HERE> # Put code here to encrypt the data
    payload["name"]["lastName"] = <UPDATE_HERE> # Put code here to encrypt the data

    # Do random fields
    if payload["name"]["otherNames"] is None:
      <UPDATE_HERE> # put code here to delete this field if None
    else:
      payload["name"]["otherNames"] = <UPDATE_HERE> # Put code here to encrypt the data
    payload["address"] = <UPDATE_HERE> # Put code here to encrypt the data
    payload["dob"] = <UPDATE_HERE> # Put code here to encrypt the data
    payload["phoneNumber"] = <UPDATE_HERE> # Put code here to encrypt the data
    payload["salary"] = <UPDATE_HERE> # Put code here to encrypt the data
    payload["taxIdentifier"] = <UPDATE_HERE> # Put code here to encrypt the data


    # Test if the data is encrypted
    for data in [ payload["name"]["firstName"], payload["name"]["lastName"], payload["address"], payload["dob"], payload["phoneNumber"], payload["salary"], payload["taxIdentifier"]]:
      if type(data) is not Binary and data.subtype != 6:
        print("Data is not encrypted")
        sys.exit(-1)

    if "otherNames" in payload["name"] and payload["name"]["otherNames"] is None:
      print("None cannot be encrypted")
      sys.exit(-1)

  except EncryptionError as e:
    print(f"Encryption error: {e}")


  print(payload)

  result = client[encrypted_db_name][encrypted_coll_name].insert_one(payload)

  print(result.inserted_id)

if __name__ == "__main__":
  main()