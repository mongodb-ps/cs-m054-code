// run via: mongosh "mongodb://sdeadmin:s3cr3t%21@mongodb-0:27017/?replicaSet=rs0" --tls --tlsCAFile /data/pki/ca.pem --eval 'load("second_day.js")'

// Create Index
db.getSiblingDB("__encryption").getCollection("__keyVault").createIndex(
  {
    keyAltNames: 1
  },
  {
    unique: true,
    partialFilterExpression: {
      "keyAltNames": {
        "$exists": true
      }
    }
  }
);

// Create DEK
const provider = {
 "kmip": { // <-- KMS provider name
    "endpoint": "kmip0:5696"
 }
};

const tlsOptions = {
  kmip: {
    tlsCAFile: "/data/pki/ca.pem",
    tlsCertificateKeyFile: "/data/pki/server.pem"
  }
};

const autoEncryptionOpts = {
 kmsProviders : provider,
 schemaMap: {}, //no schema map
 keyVaultNamespace: "__encryption.__keyVault",
 tlsOptions: tlsOptions
};

encryptedClient = Mongo("mongodb://sdeadmin:s3cr3t%21@mongodb-0:27017/?replicaSet=rs0&tls=true&tlsCAFile=%data%pki%2Fca.pem", autoEncryptionOpts);

keyVault = encryptedClient.getKeyVault();

keyVault.createKey(
 "kmip", // <-- KMS provider name
 {
   "keyId": "1"
 }, // <-- CMK info (specific to AWS in this case)
 ["dataKey1"] // <-- Key alternative name
);

// Retrieve all the keys
keyVault.getKeys();

// Create User and Role
db.getSiblingDB('admin').createRole({
 "role": "cryptoClient",
 "privileges": [
   {
      resource: {
        db: "__encryption",
        collection: "__keyVault" 
      },
      actions: [ "find" ]
    }
  ],
  "roles": [ ]
});
db.getSiblingDB('admin').createUser({
 "user": "app_user",
 "pwd": "SuperP@ssword123!",
 "roles": ["cryptoClient", {'role': "readWrite", 'db': 'companyData'} ]
});

db.getSiblingDB("companyData").createCollection("employee");

exit;