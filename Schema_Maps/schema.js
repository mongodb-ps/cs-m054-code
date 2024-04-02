db.getSiblingDB("companyData").runCommand({
  collMod: "employee",
  validator: {
    $jsonSchema: {
   "bsonType": "object",
   "encryptMetadata": {
     "keyId": [UUID("585ea3df-b644-4204-a0d3-746f62ccbbfa")], // this must be changed
     "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random",
   },
   "properties": {
     "name": {
        "bsonType": "object",
        "properties": {
          "firstName": {
            "encrypt": {
              "bsonType": "string",
              "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
            }
          },
          "lastName": {
            "encrypt": {
              "bsonType": "string",
              "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
            }
          },
          "otherNames": {
            "encrypt": {
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
}
)