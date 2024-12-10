package main

import (
	"C"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func createClient(c string, u string, p string, caFile string) (*mongo.Client, error) {
	//auth setup
	creds := options.Credential{
		Username: 		 u,
		Password: 		 p,
		AuthMechanism: "SCRAM-SHA-256",
	}

	// TLS setup
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("failed to append CA certificate")
	}

	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	// instantiate client
	opts := options.Client().ApplyURI(c).SetAuth(creds).SetTLSConfig(tlsConfig)
	client, err := mongo.Connect(context.TODO(), opts)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Function to create the MognoDB ClientEncryption instance
func createManualEncryptionClient(c *mongo.Client, kp map[string]map[string]interface{}, kns string, tlsOps map[string]*tls.Config) (*mongo.ClientEncryption, error) {
	o := options.ClientEncryption().SetKeyVaultNamespace(kns).SetKmsProviders(kp).SetTLSConfig(tlsOps)
	client, err := mongo.NewClientEncryption(c, o)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Function to perform the manual encryption
func encryptManual(ce *mongo.ClientEncryption, dek primitive.Binary, alg string, data interface{}) (primitive.Binary, error) {
	var out primitive.Binary
	rawValueType, rawValueData, err := bson.MarshalValue(data)
	if err != nil {
		return primitive.Binary{}, err
	}

	rawValue := bson.RawValue{Type: rawValueType, Value: rawValueData}

	encryptionOpts := options.Encrypt().
		SetAlgorithm(alg).
		SetKeyID(dek)

	out, err = <UPDATE_HERE> // PUT CODE HERE TO MANUALLY ENCRYPT
	if err != nil {
		return primitive.Binary{}, err
	}

	return out, nil
}

func main() {
	var (
		keyVaultDB 		 		= "__encryption"
		keyVaultColl 	 		= "__keyVault"
		keySpace         	= keyVaultDB + "." + keyVaultColl
		caFile			 			= "/data/pki/ca.pem"
		username 		 			= "app_user"
		password		 			= <UPDATE_HERE>
		connectionString 	= "mongodb://mongodb-0:27017/?replicaSet=rs0&tls=true"
		clientEncryption 	*mongo.ClientEncryption
		client           	*mongo.Client
		exitCode         	= 0
    kmipTLSConfig   	*tls.Config
		result           	*mongo.InsertOneResult
		dekFindResult    	bson.M
		dek              	primitive.Binary
		err				 				error
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
	client, err = createClient(connectionString, username, password, caFile)
	if err != nil {
		fmt.Printf("MDB client error: %s\n", err)
		exitCode = 1
		return
	}

	coll := client.Database("__encryption").Collection("__keyVault")

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

	payload := bson.M{
    "name": bson.M{
      "firstName": "Manish",
      "lastName": "Engineer",
      "otherNames": nil,
    },
    "address": bson.M{
      "streetAddress": "1 Bson Street",
      "suburbCounty": "Mongoville",
      "stateProvince": "Victoria",
      "zipPostcode": "3999",
      "country": "Oz",
    },
    "dob": time.Date(1980, 10, 10, 0, 0, 0, 0, time.Local),
    "phoneNumber": "1800MONGO",
    "salary": 999999.99,
    "taxIdentifier": "78SD20NN001",
    "role": []string{"CTO"},
  }

	// Retrieve our DEK
	opts := options.FindOne().SetProjection(bson.D{{Key: "_id", Value: 1}})
	err = coll.FindOne(context.TODO(), bson.D{<UPDATE_HERE> // query for DEK}, opts).Decode(&dekFindResult)
	if err != nil || len(dekFindResult) == 0 {
		fmt.Printf("DEK find error: %s\n", err)
		exitCode = 1
		return
	}
	dek = dekFindResult["_id"].(primitive.Binary)

	// WRITE CODE HERE to call the the encryptManual() function that is written above
	// YOU WILL NEED TO EDIT THE encryptManual() function to perform the encryption
	// Don't forget to handle to event of name.otherNames being null
	name := payload["name"].(bson.M)
	if name["otherNames"] == nil {
		// put code here to remove this field if nil
	} else {
		name["otherNames"], err = encryptManual(<UPDATE_HERE>// put required variables here)
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}
	}

	name["firstName"], err = encryptManual(<UPDATE_HERE>// put required variables here)
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	name["lastName"], err = encryptManual(<UPDATE_HERE>// put required variables here)
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}
	payload["name"] = name

	payload["address"], err = encryptManual(<UPDATE_HERE>// put required variables here)
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	payload["dob"], err = encryptManual(<UPDATE_HERE>// put required variables here)
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	payload["phoneNumber"], err = encryptManual(<UPDATE_HERE>// put required variables here)
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	payload["salary"], err = encryptManual(<UPDATE_HERE>// put required variables here)
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	payload["taxIdentifier"], err = encryptManual(<UPDATE_HERE>// put required variables here)
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	coll = client.Database("companyData").Collection("employee")

	result, err = coll.InsertOne(context.TODO(), payload)
	if err != nil {
		fmt.Printf("Insert error: %s\n", err)
		exitCode = 1
		return
	}
	fmt.Print(result.InsertedID)

	exitCode = 0
}
