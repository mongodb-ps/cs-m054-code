try:
  import sys
  import boto3
  from bson.binary import STANDARD, Binary, UUID_SUBTYPE
  from bson.codec_options import CodecOptions
  from botocore.exceptions import ClientError
  from datetime import datetime
  from pymongo import MongoClient, UpdateOne
  from pymongo.encryption_options import AutoEncryptionOpts
  from pymongo.errors import EncryptionError, ServerSelectionTimeoutError, ConnectionFailure
  from urllib.parse import quote_plus
  import names
except ImportError as e:
  print(e)
  sys.exit(-1)

# IN VALUES HERE!
STUDENTNAME = 
MDB_PASSWORD = 
APP_USER = "app_user"
CA_PATH = "/home/ubuntu/ca.cert"

def mdb_client(connection_string, auto_encryption_opts=None):
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
    client = MongoClient(connection_string, auto_encryption_opts=auto_encryption_opts)
    client.admin.command('hello')
    return client, None
  except (ServerSelectionTimeoutError, ConnectionFailure) as e:
    return None, f"Cannot connect to database, please check settings in config file: {e}"

def getAWSToken():
  try:
    sts_client = boto3.client('sts')
    # Call the assume_role method of the STSConnection object and pass the role
    # ARN and a role session name.
    assumed_role_object=sts_client.assume_role(
        RoleArn="arn:aws:iam::331472312345:role/ce-training-kms",
        RoleSessionName="applicationSession",
        DurationSeconds=3600
    )
    return assumed_role_object['Credentials']
  except ClientError as e:
    return None, e
  
def create_employee():
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
  return payload
  
def main():

  # Obviously this should not be hardcoded
  connection_string = "mongodb://%s:%s@%s02.mdbps.internal/?serverSelectionTimeoutMS=5000&tls=true&tlsCAFile=%s" % (
    quote_plus(APP_USER),
    quote_plus(MDB_PASSWORD),
    STUDENTNAME,
    quote_plus(CA_PATH)
  )

  # Declare or key vault namespce
  keyvault_db = "__encryption"
  keyvault_coll = "__keyVault"
  keyvault_namespace = f"{keyvault_db}.{keyvault_coll}"

  assumed_role_object = getAWSToken()

  # declare our key provider type
  provider = "aws"

  # declare our key provider attributes
  kms_provider = {
    provider: {
      "accessKeyId": assumed_role_object['AccessKeyId'],
      "secretAccessKey": assumed_role_object['SecretAccessKey'],
      "sessionToken": assumed_role_object['SessionToken']
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

  # retrieve the DEK UUID
  data_key_id_1 = client[keyvault_db][keyvault_coll].find_one({"keyAltNames": "dataKey1"},{"_id": 1})["_id"]
  if data_key_id_1 is None:
    print("Failed to find DEK")
    sys.exit()
  
  encrypted_db_name = "companyData"
  encrypted_coll_name = "employee"

  schema_map = {
    "companyData.employee": {
      "bsonType": "object",
      "encryptMetadata": {
        "keyId": data_key_id_1,
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
    schema_map = {schema_map},
    kms_tls_options = {
      "kmip": {
        "tlsCAFile": "/home/ubuntu/ca.cert",
        "tlsCertificateKeyFile": "/home/ubuntu/server.pem"
      }
    },
    crypt_shared_lib_required = True,
    mongocryptd_bypass_spawn = True,
    crypt_shared_lib_path = '/lib/mongo_crypt_v1.so'
  )

  secure_client, err = mdb_client(connection_string, auto_encryption_opts=auto_encryption)
  if err is not None:
    print(err)
    sys.exit(1)

  #unencrypted_new_docs = []
  #for i in range(10001):
  #  unencrypted_new_docs.append(create_employee())
  #client[encrypted_db_name][encrypted_coll_name].insert_many(unencrypted_new_docs)

  unencrypt_docs = client[encrypted_db_name][encrypted_coll_name].find({"name.firstName": {"$type": "string"}})

  for doc in unencrypt_docs:
    update_list = []
    for i in range(10000):
      update_list.append(UpdateOne({"_id": doc["_id"]},{"$set": doc}))
    secure_client.bulk_write(update_list)

if __name__ == "__main__":
  main()