try:
  from os import path
  from datetime import datetime
  from urllib.parse import quote_plus
  import sys
  import names
  from random import randint

  from pymongo.encryption_options import AutoEncryptionOpts
  from utils.utils import check_python_version, test_encrypted
  from mongodb.mdb import MDB, ALG
except ImportError as e:
  from os import path
  print(f"Import error for {path.basename(__file__)}: {e}")
  exit(1)


# PUT VALUES HERE!

MDB_PASSWORD = <UPDATE_HERE> 
APP_USER = "app_user"
CA_PATH = "/data/pki/ca.pem"
TLSKEYCERT_PATH = "/data/pki/client-0.pem"
SHARED_LIB_PATH = '/data/lib/mongo_crypt_v1.so'
KMIP_ADDR = <UPDATE_HERE> # Update for KMIP address and port, e.g. `hostname:port`

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

  employee_id = str("%05d" % randint(0,99999))
  firstname = names.get_first_name()
  lastname = names.get_last_name()

  payload = {
    "_id": employee_id, # we are using this as out keyAltName
    "name": {
      "firstName": "",
      "lastName": "",
      "otherNames": None,
    },
    "address": {
      "streetAddress": "3 Bson Street",
      "suburbCounty": "Mongoville",
      "stateProvince": "Victoria",
      "zipPostcode": "3999",
      "country": "Oz"
    },
    "dob": datetime(1978, 10, 10),
    "phoneNumber": "1800MONGO",
    "salary": 999999.99,
    "taxIdentifier": "78SD20NN001",
    "role": [
      "CIO"
    ]
  }
  
  encrypted_db_name = "companyData"
  encrypted_coll_name = "employee"

  schema_map = {
    "companyData.employee": {
      "bsonType": "object",
      "encryptMetadata": {
        "keyId": <UPDATE_HERE>, # PUT APPROPRIATE CODE OR VARIABLE HERE
        "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
      },
      "properties": {
        "name": {
          "bsonType": "object",
          "properties": {
            "otherNames": {
              "encrypt" : {
                "bsonType": "string"
              }
            }
          }
        },
        "address": {
          "encrypt": {
            "bsonType": "object"
          }
        },
        "dob": {
          "encrypt": {
            "bsonType": "date"
          }
        },
        "phoneNumber": {
          "encrypt": {
            "bsonType": "string"
          }
        },
        "salary": {
          "encrypt": {
            "bsonType": "double"
          }
        },
        "taxIdentifier": {
          "encrypt": {
            "bsonType": "string"
          }
        }
      }
    }
  }

  auto_encryption = AutoEncryptionOpts(
    kms_provider_details,
    keyvault_namespace,
    schema_map = schema_map,
    kms_tls_options = {
      "kmip": {
        "tlsCAFile": CA_PATH,
        "tlsCertificateKeyFile": TLSKEYCERT_PATH
      }
    },
    crypt_shared_lib_required = True,
    mongocryptd_bypass_spawn = True,
    crypt_shared_lib_path = SHARED_LIB_PATH 
  )

  # Instantiate our MDB class
  mdb = MDB(connection_string, kms_name, kms_provider_details, keyvault_namespace, CA_PATH, TLSKEYCERT_PATH)

  # Create the ClientEncryption object so we can create and retrieve DEKs
  fail = mdb.create_client_encryption()
  if fail is not None:
    print(fail)
    sys.exit(1)

  # Retrieve or create the DEK UUID
  employee_key_id = mdb.create_get_dek_uuid(employee_id, "1")
  if employee_key_id is None:
    print("Failed to find DEK")
    sys.exit()

  # Create the encrypted client in our MDB class
  fail = mdb.create_encrypted_client(auto_encryption)
  if fail is not None:
    print(fail)
    sys.exit(1)

  # ENCRYPT THE name.firstName and name.lastName here
  payload["name"]["firstName"] = mdb.encrypt_field(firstname, ALG.DET, employee_key_id)
  payload["name"]["lastName"] = mdb.encrypt_field(lastname, ALG.DET, employee_key_id)

  # Test if the data is encrypted
  for data in [payload["name"]["firstName"], payload["name"]["lastName"]]:
    encrypted = test_encrypted(data)
    if not encrypted:
      print("Data is not encrypted")
      sys.exit()

  # remove `name.otherNames` if None because wwe cannot encrypt none
  if payload["name"]["otherNames"] == None:
    del(payload["name"]["otherNames"])

  result = mdb.encrypted_insert_one(encrypted_db_name, encrypted_coll_name, payload)
  print(result.inserted_id)
  
  enc_first_name = mdb.encrypt_field(firstname, ALG.DET, employee_key_id)
  enc_last_name = mdb.encrypt_field(lastname, ALG.DET, employee_key_id)
  result = mdb.encrypted_find_one(encrypted_db_name, encrypted_coll_name, {"name.firstName": enc_first_name, "name.lastName": enc_last_name})

  print(result)

if __name__ == "__main__":
  main()