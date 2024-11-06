// run via: mongosh "mongodb://mongoadmin:passwordone@<STUDENTNAME>.mdbps.internal:27017/?replicaSet=rs0" --tls --tlsCAFile /data/pki/ca.pem --eval 'load("second_day.js")'

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
    "endpoint": <UPDATE_HERE>
 }
};

const tlsOptions = {
  kmip: {
    tlsCAFile: "/data/pki/ca.pem",
    tlsCertificateKeyFile: "/data/pki/client-0.pem"
  }
};

const autoEncryptionOpts = {
 kmsProviders : provider,
 schemaMap: {}, //no schema map
 keyVaultNamespace: "__encryption.__keyVault",
 tlsOptions: tlsOptions
};

encryptedClient = Mongo("mongodb://mongoadmin:passwordone@<STUDENTNAME>.mdbps.internal:27017/?replicaSet=rs0&tls=true&tlsCAFile=%2Fhome%2Fubuntu%2Fca.cert", autoEncryptionOpts);

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
//use admin;
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
 "pwd": "password123",
 "roles": ["cryptoClient", {'role': "readWrite", 'db': 'companyData'} ]
});

db.getSiblingDB("companyData").createCollection("employee");

exit;