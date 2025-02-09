try:
  from os import path
  from datetime import datetime
  from urllib.parse import quote_plus
  import sys
  import names
  from pymongo.encryption_options import AutoEncryptionOpts
  from utils.utils import check_python_version
  from mongodb.mdb import MDB
except ImportError as e:
  from os import path
  print(f"Import error for {path.basename(__file__)}: {e}")
  exit(1)

# PUT VALUES HERE!

MDB_PASSWORD = "SuperP@ssword123!"
APP_USER = "app_user"
CA_PATH = "/data/pki/ca.pem"
TLSKEYCERT_PATH = "/data/pki/client-0.pem"

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
      "endpoint": "kmip-0:5696"
    }
  }
  
  # declare our database and collection
  encrypted_db_name = "companyData"
  encrypted_coll_name = "employee"

  firstname = names.get_first_name()
  lastname = names.get_last_name()
  payload = {
    "name": {
      "firstName": firstname,
      "lastName": lastname,
      "otherNames": None,
    },
    "address": {
      "streetAddress": "2 Bson Street",
      "suburbCounty": "Mongoville",
      "stateProvince": "Victoria",
      "zipPostcode": "3999",
      "country": "Oz"
    },
    "dob": datetime(1980, 10, 11),
    "phoneNumber": "1800MONGO",
    "salary": 999999.99,
    "taxIdentifier": "78SD20NN001",
    "role": [
      "CIO"
    ]
  }
  
  encrypted_db_name = "companyData"
  encrypted_coll_name = "employee"
  
  # Instantiate our MDB class
  mdb = MDB(connection_string, None, kms_provider, keyvault_namespace, CA_PATH, TLSKEYCERT_PATH)

  # Retrieve the DEK UUID
  data_key_id_1 = mdb.get_dek_uuid("dataKey1")
  if data_key_id_1 is None:
    print("Failed to find DEK")
    sys.exit()

  # Define our encrypted schema
  schema_map = {
    "companyData.employee": {
      "bsonType": "object",
      "encryptMetadata": {
        "keyId": [data_key_id_1],
        "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
      },
      "properties": {
        "name": {
          "bsonType": "object",
          "properties": {
            "firstName": {
              "encrypt" : {
                "bsonType": "string",
                "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
              }
            },
            "lastName": {
              "encrypt" : {
                "bsonType": "string",
                "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
              }
            },
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
    kms_provider,
    keyvault_namespace,
    schema_map = schema_map,
    kms_tls_options = {
      "kmip": {
        "tlsCAFile": "/data/pki/ca.pem",
        "tlsCertificateKeyFile": "/data/pki/client-0.pem"
      }
    },
    crypt_shared_lib_required = True,
    mongocryptd_bypass_spawn = True,
    crypt_shared_lib_path = '/data/lib/mongo_crypt_v1.so'
  )

  if payload["name"]["otherNames"] is None:
    del(payload["name"]["otherNames"])

  # Create the encrypred client in our MDB class
  success = mdb.create_encrypted_client(auto_encryption)
  if success is not None:
    print(success)
    sys.exit(1)

  result = mdb.encrypted_insert_one(encrypted_db_name, encrypted_coll_name, payload)
  print(result.inserted_id)

  decrypted_doc = mdb.encrypted_find_one(encrypted_db_name, encrypted_coll_name, {"name.firstName": firstname})

  print(decrypted_doc)

if __name__ == "__main__":
  main()