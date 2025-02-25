try:
  from os import path
  from datetime import datetime
  from urllib.parse import quote_plus
  import sys
  import dpath
  from mongodb.mdb import MDB, ALG
  from utils.utils import check_python_version, test_encrypted
except ImportError as e:
  from os import path
  print(f"Import error for {path.basename(__file__)}: {e}")
  exit(1)


# PUT VALUES HERE!
MDB_PASSWORD = "SuperP@ssword123!"
APP_USER = "app_user"
CA_PATH = "/data/pki/ca.pem"
TLSKEYCERT_PATH = "/data/pki/client-0.pem"
KMIP_ADDR = "kmip-0:5696"

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
  kms_name = "kmip"

  # declare our key provider attributes
  kms_provider_details = {
    kms_name: {
      "endpoint": KMIP_ADDR
    }
  }
  
  # declare our database and collection
  encrypted_db_name = "companyData"
  encrypted_coll_name = "employee"

  payload = {
    "name": {
      "firstName": "Kuber",
      "lastName": "Engineer",
      "otherNames": None,
    },
    "address": {
      "streetAddress": "12 Bson Street",
      "suburbCounty": "Mongoville",
      "stateProvince": "Victoria",
      "zipPostcode": "3999",
      "country": "Oz"
    },
    "dob": datetime(1981, 11, 11),
    "phoneNumber": "1800MONGO",
    "salary": 999999.99,
    "taxIdentifier": "78SDSSNN001",
    "role": [
      "DEV"
    ]
  }

  encrypted_fields = ["name/firstName", "name/lastName", "address", "dob", "phoneNumber", "salary", "taxIdentifier"]
  det_encrypted_fields = ["name/firstName", "name/lastName"]
  rand_encrypted_fields = ["address", "dob", "phoneNumber", "salary", "taxIdentifier"]
  
  # Instantiate our MDB class
  mdb = MDB(connection_string, kms_name, kms_provider_details, keyvault_namespace, CA_PATH, TLSKEYCERT_PATH)

  # Create the ClientEncryption object so we can create and retrieve DEKs
  fail = mdb.create_client_encryption()
  if fail is not None:
    print(fail)
    sys.exit(1)

  # Retrieve the DEK UUID
  data_key_id_1 = mdb.get_dek_uuid("dataKey1")
  if data_key_id_1 is None:
    print("Failed to find DEK")
    sys.exit()

  # Encrypt our deterministic fields
  for field in det_encrypted_fields:
    current_value = dpath.get(payload, field)
    new_value = mdb.encrypt_field(current_value, ALG.DET, data_key_id_1)
    dpath.set(payload, field, new_value)

  # Check for "None" value
  if payload["name"]["otherNames"] is None:
    del(payload["name"]["otherNames"])
  else:
    payload["name"]["otherNames"] = mdb.encrypt_field(payload["name"]["otherNames"], ALG.RAND, data_key_id_1)

  # Encrypt our random fields
  for field in rand_encrypted_fields:
    current_value = dpath.get(payload, field)
    new_value = mdb.encrypt_field(current_value, ALG.RAND, data_key_id_1)
    dpath.set(payload, field, new_value)

  # Test if the data is encrypted
  for data in encrypted_fields:
    encrypted = test_encrypted(dpath.get(payload, data))
    if not encrypted:
      print("Data is not encrypted")
      sys.exit()

  # Extra test
  if "otherNames" in payload["name"] and payload["name"]["otherNames"] is None:
    print("None cannot be encrypted")
    sys.exit(-1)

  # Insert our document with encrypted values
  result = mdb.insert_one(encrypted_db_name, encrypted_coll_name, payload)
  print(result.inserted_id)

  # Encrypt our query value
  encrypted_name = mdb.encrypt_field("Kuber", ALG.DET, data_key_id_1)

  # Query for our document
  encrypted_doc = mdb.find_one(encrypted_db_name, encrypted_coll_name, {"name.firstName": encrypted_name})
  print(encrypted_doc)

  # Decrypt our document
  decrypted_doc = mdb.decrypt_fields(encrypted_doc)
  print(decrypted_doc)


if __name__ == "__main__":
  main()