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
		Username:      u,
		Password:      p,
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

	out, err = ce.Encrypt(context.TODO(), rawValue, encryptionOpts)
	if err != nil {
		return primitive.Binary{}, err
	}

	return out, nil
}

func decryptManual(c *mongo.ClientEncryption, d primitive.Binary) (bson.RawValue, error) {
	out, err := c.Decrypt(context.TODO(), d)
	if err != nil {
		return bson.RawValue{}, err
	}

	return out, nil
}

// Function that traverses a BSON object and determines if the type is a primitive,
// if so, we check if this is a binary subtype 6 and then call the manual decrypt function
// to decrypt the value. We call the same function if arrays or subdocuments are found
func traverseBson(c *mongo.ClientEncryption, d bson.M) (bson.M, error) {
	for k, v := range d {
		a, ok := v.(primitive.M)
		if ok {
			data, err := traverseBson(c, a)
			if err != nil {
				return bson.M{}, err
			}
			d[k] = data
		} else {
			// Check if binary Subtype 6 data, e.g. encrypted. Skip if it is not
			i, ok := v.(primitive.Binary)
			if !ok {
				// not binary data
				continue
			}
			if i.Subtype == 6 {
				data, err := decryptManual(c, i)
				if err != nil {
					return bson.M{}, err
				}
				d[k] = data
			}
		}
	}
	return d, nil
}

func main() {
	var (
		keyVaultDB       = "__encryption"
		keyVaultColl     = "__keyVault"
		keySpace         = keyVaultDB + "." + keyVaultColl
		caFile           = "/data/pki/ca.pem"
		username         = "app_user"
		password         = "SuperP@ssword123!"
		connectionString = "mongodb://mongodb-0:27017/?replicaSet=rs0&tls=true"
		clientEncryption *mongo.ClientEncryption
		client           *mongo.Client
		exitCode         = 0
		kmipTLSConfig    *tls.Config
		result           *mongo.InsertOneResult
		dekFindResult    bson.M
		dek              primitive.Binary
		encryptedName    primitive.Binary
		findResult       bson.M
		outputData       bson.M
		err              error
	)

	defer func() {
		os.Exit(exitCode)
	}()

	provider := "kmip"
	kmsProvider := map[string]map[string]interface{}{
		provider: {
			"endpoint": "kmip-0:5696",
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
		"tlsCAFile":             "/data/pki/ca.pem",
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
			"firstName":  "Kuber",
			"lastName":   "Engineer",
			"otherNames": nil,
		},
		"address": bson.M{
			"streetAddress": "12 Bson Street",
			"suburbCounty":  "Mongoville",
			"stateProvince": "Victoria",
			"zipPostcode":   "3999",
			"country":       "Oz",
		},
		"dob":           time.Date(1981, 11, 11, 0, 0, 0, 0, time.Local),
		"phoneNumber":   "1800MONGO",
		"salary":        999999.99,
		"taxIdentifier": "78SDSSNN001",
		"role":          []string{"DEV"},
	}

	// Retrieve our DEK
	opts := options.FindOne().SetProjection(bson.D{{Key: "_id", Value: 1}})
	err = coll.FindOne(context.TODO(), bson.D{{Key: "keyAltNames", Value: "dataKey1"}}, opts).Decode(&dekFindResult)
	if err != nil || len(dekFindResult) == 0 {
		fmt.Printf("DEK find error: %s\n", err)
		exitCode = 1
		return
	}
	dek = dekFindResult["_id"].(primitive.Binary)

	// remove the otherNames field if it is nil
	name := payload["name"].(bson.M)
	if name["otherNames"] == nil {
		fmt.Println("Removing nil")
		delete(name, "otherNames")
	} else {
		name["otherNames"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", name["otherNames"])
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}
	}

	name["firstName"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", name["firstName"])
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	name["lastName"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", name["lastName"])
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}
	payload["name"] = name

	payload["address"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", payload["address"])
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	payload["dob"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", payload["dob"])
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	payload["phoneNumber"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", payload["phoneNumber"])
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	payload["salary"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", payload["salary"])
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	payload["taxIdentifier"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", payload["taxIdentifier"])
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

	encryptedName, err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", "Kuber")
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}
	err = coll.FindOne(context.TODO(), bson.M{"name.firstName": encryptedName}).Decode(&findResult)
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

	outputData, err = traverseBson(clientEncryption, findResult)
	if err != nil {
		fmt.Printf("Encryption error: %s\n", err)
		exitCode = 1
		return
	}
	fmt.Printf("%+v\n", outputData)

	exitCode = 0
}
