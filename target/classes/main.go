package main

import (
	"C"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"
	"encoding/base64"

	"go.mongodb.org/mongo-driver/v2/bson"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"github.com/goombaio/namegenerator"
)

var (
	
	MDB_PASSWORD =
)

func createClient(c string) (*mongo.Client, error) {
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(c))

	if err != nil {
		return nil, err
	}

	return client, nil
}

func createManualEncryptionClient(c *mongo.Client, kp map[string]map[string]interface{}, kns string, tlsOps map[string]*tls.Config) (*mongo.ClientEncryption, error) {
	o := options.ClientEncryption().SetKeyVaultNamespace(kns).SetKmsProviders(kp).SetTLSConfig(tlsOps)
	client, err := mongo.NewClientEncryption(c, o)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func createAutoEncryptionClient(c string, ns string, kms map[string]map[string]interface{}, tlsOps map[string]*tls.Config, s bson.M) (*mongo.Client, error) {
	extraOptions := map[string]interface{}{
		"cryptSharedLibPath":     "/data/lib/mongo_crypt_v1.so",
		"cryptSharedLibRequired": true,
	}
	autoEncryptionOpts := options.AutoEncryption().
		SetKeyVaultNamespace(ns).
		SetKmsProviders(kms).
		SetSchemaMap(s).
		SetTLSConfig(tlsOps).
		SetExtraOptions(extraOptions)

	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(c).SetAutoEncryptionOptions(autoEncryptionOpts))

	if err != nil {
		return nil, err
	}

	return client, nil
}

func createDEK(c *mongo.ClientEncryption, kn string, cmk map[string]interface{}, altName string) (Binary, error) {
	var (
		dek Binary
		err error
	)

	cOpts := options.DataKey().
		SetMasterKey(cmk).
		SetKeyAltNames([]string{altName})
	dek, err = c.CreateDataKey(context.TODO(), kn, cOpts)
	if err != nil {
		return Binary{}, err
	}

	return dek, nil
}

func getDEK(c *mongo.ClientEncryption, altName string) (Binary, error) {
	var dekFindResult bson.M

	err := c.GetKeyByAltName(context.TODO(), altName).Decode(&dekFindResult)
	if err != nil {
		return Binary{}, err
	}
	if len(dekFindResult) == 0 {
		return Binary{}, nil
	}
	b, ok := dekFindResult["_id"].(Binary)
	if !ok {
		return Binary{}, errors.New("the DEK conversion error")
	}
	return b, nil
}

func trashDEK(c *mongo.ClientEncryption, kp map[string]map[string]interface{}, kns string, keyID Binary) error {
	var (
		delResult *mongo.DeleteResult
		err       error
	)

	delResult, err = c.DeleteKey(context.TODO(), keyID)
	if err != nil {
		return err
	}
	if delResult.DeletedCount == 0 {
		return errors.New("no DEK deleted")
	}

	return nil
}

func nameGenerator()(string, string) {
	seed := time.Now().UTC().UnixNano()
	nameGenerator := namegenerator.NewNameGenerator(seed)

	name := nameGenerator.Generate()

	firstName := strings.Split(name, "-")[0]
	lastName := strings.Split(name, "-")[1]

	return firstName, lastName
}

func main() {
	var (
		client           *mongo.Client
		clientEncryption *mongo.ClientEncryption
		connectionString = "mongodb://app_user:" + MDB_PASSWORD + "@mongodb-0:27017/?replicaSet=rs0&tls=true&tlsCAFile=%2Fdata%2Fpki%2Fca.pem"
		dek              Binary
		employeeDEK      Binary
		encryptedClient  *mongo.Client
		err							 error
		exitCode         = 0
		findResult			 bson.M
		keyVaultColl 		 = "__keyVault"
		keyVaultDB 			 = "__encryption"
		
		kmipTLSConfig    *tls.Config
		result           *mongo.InsertOneResult
	)

	defer func() {
		os.Exit(exitCode)
	}()

	provider := "kmip"
	kmsProvider := map[string]map[string]interface{}{
		provider: {
			"endpoint": <UPDATE_HERE>
		},
	}
	cmk := map[string]interface{}{
		"keyId": "1", // this is our CMK ID
	}
	keySpace := keyVaultDB + "." + keyVaultColl

	client, err = createClient(connectionString)
	if err != nil {
		fmt.Printf("MDB client error: %s\n", err)
		exitCode = 1
		return
	}

	// Set the KMIP TLS options
	kmsTLSOptions := make(map[string]*tls.Config)
	tlsOptions := map[string]interface{}{
		"tlsCAFile": "/data/pki/ca.pem",
		"tlsCertificateKeyFile": "/data/pki/client-0.pem",
	}
	kmipTLSConfig, err = options.BuildTLSConfig(tlsOptions)
	if err != nil {
		fmt.Printf("Cannot create KMS TLS Config: %s\n", err)
		exitCode = 1
		return
	}
	kmsTLSOptions["kmip"] = kmipTLSConfig
	
	clientEncryption, err = createManualEncryptionClient(client, kmsProvider, keySpace, kmsTLSOptions)
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	rand.Seed(time.Now().UnixNano())
	id := strconv.Itoa(int(rand.Intn(100000)))

	// get our employee DEK or create
	employeeDEK, err = getDEK(clientEncryption, id)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			employeeDEK, err = createDEK(clientEncryption, provider, cmk, id)
			if err != nil {
				fmt.Printf("Cannot create employee DEK: %s\n", err)
				exitCode = 1
				return
			}
		} else {
			fmt.Printf("Cannot get employee DEK: %s\n", err)
			exitCode = 1
			return
		}
	}
	
	firstname, lastname := nameGenerator()
  payload := bson.M{
		"_id": id,
    "name": bson.M{
      "firstName": firstname,
      "lastName": lastname,
      "otherNames": nil,
    },
    "address": bson.M{
      "streetAddress": "29 Bson Street",
      "suburbCounty": "Mongoville",
      "stateProvince": "Victoria",
      "zipPostcode": "3999",
      "country": "Oz",
    },
    "dob": time.Date(1999, 1, 12, 0, 0, 0, 0, time.Local),
    "phoneNumber": "1800MONGO",
    "salary": 999999.99,
    "taxIdentifier": "78SDSSWN001",
    "role": []string{"Student"},
  }

	// Retrieve our DEK
	dek, err = getDEK(clientEncryption, "dataKey1")
	if err != nil {
		fmt.Printf("DEK find error: %s\n", err)
		exitCode = 1
		return
	}

	db := "companyData"
	collection := "employee"
	
	schemaMap := `{
		"bsonType": "object",
		"encryptMetadata": {
			"keyId": "/_id",
			"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
		},
		"properties": {
			"name": {
				"bsonType": "object",
				"properties": {
					"firstName": {
						"encrypt": {
							"keyId": [ 
								{
									"$binary": {
										"base64": "` + base64.StdEncoding.EncodeToString(dek.Data) + `",
										"subType": "04"
									}
								}
							],
							"bsonType": "string",
							"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
						 }
					},
					"lastName": {
						"encrypt": {
							"keyId": [ 
								{
									"$binary": {
										"base64": "` + base64.StdEncoding.EncodeToString(dek.Data) + `",
										"subType": "04"
									}
								}
							],
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
		}`

	// Auto Encryption Client
	var testSchema bson.Raw
	err = bson.UnmarshalExtJSON([]byte(schemaMap), true, &testSchema)
	if err != nil {
		fmt.Printf("Unmarshal Error: %s\n", err)
	}
	completeMap := map[string]interface{}{
		db + "." + collection: testSchema,
	}
	encryptedClient, err = createAutoEncryptionClient(connectionString, keySpace, kmsProvider, kmsTLSOptions, completeMap)
	if err != nil {
		fmt.Printf("MDB encrypted client error: %s\n", err)
		exitCode = 1
		return
	}

	encryptedColl := encryptedClient.Database(db).Collection(collection)

	// remove the otherNames field if it is nil
	name := payload["name"].(bson.M)
	if name["otherNames"] == nil {
		fmt.Println("Removing nil")
		delete(name, "otherNames")
	}

	result, err = encryptedColl.InsertOne(context.TODO(), payload)
	if err != nil {
		fmt.Printf("Insert error: %s\n", err)
		exitCode = 1
		return
	}
	fmt.Print(result.InsertedID)

	err = encryptedColl.FindOne(context.TODO(), bson.M{"name.firstName": firstname}).Decode(&findResult)
	if err != nil {
		fmt.Printf("MongoDB find error: %s\n", err)
		exitCode = 1
		return
	}
	if len(findResult) == 0 {
		fmt.Println("Cannot find document")
		exitCode = 1
		return
	}
	fmt.Printf("%+v\n", findResult)

	err = trashDEK(clientEncryption, kmsProvider, keySpace, employeeDEK)
	if err != nil {
		fmt.Printf("DEK deletion error: %s", err)
	}
	time.Sleep(61 * time.Second)

	err = encryptedColl.FindOne(context.TODO(), bson.M{"name.firstName": firstname}).Decode(&findResult)
	if err != nil {
		fmt.Printf("MongoDB find error: %s\n", err)
		exitCode = 1
		return
	}
	if len(findResult) == 0 {
		fmt.Println("Cannot find document")
		exitCode = 1
		return
	}
	fmt.Printf("%+v\n", findResult)

	exitCode = 0
}
