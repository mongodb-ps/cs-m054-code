package main

import (
	"C"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	mdb "sde/manual_complete/mongodb"
	"sde/manual_complete/utils"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	var (
		keyVaultDB       = "__encryption"
		keyVaultColl     = "__keyVault"
		keySpace         = keyVaultDB + "." + keyVaultColl
		caFile           = "/data/pki/ca.pem"
		keyCertFile      = "/data/pki/client-0.pem"
		username         = "app_user"
		password         = "SuperP@ssword123!"
		connectionString = "mongodb://mongodb-0:27017/?replicaSet=rs0&tls=true"
		exitCode         = 0
		kmipTLSConfig    *tls.Config
		result           *mongo.InsertOneResult
		dekFindResult    bson.M
		dek              primitive.Binary
		encryptedName    primitive.Binary
		findResult       bson.M
		outputData       bson.M
		err              error
		encryptedDB      = "companyData"
		encryptedColl    = "employee"
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

	// Set the KMIP TLS options
	kmsTLSOptions := make(map[string]*tls.Config)
	tlsOptions := map[string]interface{}{
		"tlsCAFile":             caFile,
		"tlsCertificateKeyFile": keyCertFile,
	}
	kmipTLSConfig, err = options.BuildTLSConfig(tlsOptions)
	if err != nil {
		fmt.Printf("Cannot create KMS TLS Config: %s\n", err)
		exitCode = 1
		return
	}
	kmsTLSOptions["kmip"] = kmipTLSConfig

	mdb, err := mdb.NewMDB(connectionString, username, password, caFile, kmsProvider, keySpace, kmsTLSOptions)
	if err != nil {
		fmt.Printf("MDB client error: %s\n", err)
		exitCode = 1
		return
	}

	err = mdb.CreateManualEncryptionClient()
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

	// Retrieve our DEK or fail if missing
	dek, err = mdb.Get_dek_uuid("dataKey1")
	if err != nil || len(dekFindResult) == 0 {
		fmt.Printf("DEK find error: %s\n", err)
		exitCode = 1
		return
	}

	detFields := []string{"name.firstName", "name.lastName"}
	randFields := []string{"address", "dob", "phoneNumber", "salary", "taxIdentifier"}
	allEncryptedFields := append(detFields, randFields...)

	// Encrypt the payload
	for _, field := range detFields {
		tempVal, err := mdb.EncryptManual(dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", gjson.Get(payload, field))
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}
		sjson.Set(payload, field, tempVal)
	}

	for _, field := range randFields {
		tempVal, err := mdb.EncryptManual(dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", gjson.Get(payload, field))
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}
		sjson.Set(payload, field, tempVal)
	}

	// remove the otherNames field if it is nil or encrypted
	middleName := gjson.Get(payload, "name.otherNames")
	if middleName.Exists() {
		tempVal, err := mdb.EncryptManual(dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", middleName)
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}
		sjson.Set(payload, "name.otherNames", tempVal)
	} else {
		sjson.Delete(payload, "name.otherNames")
	}
	/*
		name := payload["name"].(bson.M)
		if name["otherNames"] == nil {
			fmt.Println("Removing nil")
			delete(name, "otherNames")
		} else {
			name["otherNames"], err = mdb.EncryptManual(dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", name["otherNames"])
			if err != nil {
				fmt.Printf("ClientEncrypt error: %s\n", err)
				exitCode = 1
				return
			}
		}

		name["firstName"], err = mdb.EncryptManual(dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", name["firstName"])
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}

		name["lastName"], err = mdb.EncryptManual(dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", name["lastName"])
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}
		payload["name"] = name

		payload["address"], err = mdb.EncryptManual(dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", payload["address"])
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}

		payload["dob"], err = mdb.EncryptManual(dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", payload["dob"])
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}

		payload["phoneNumber"], err = mdb.EncryptManual(dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", payload["phoneNumber"])
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}

		payload["salary"], err = mdb.EncryptManual(dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", payload["salary"])
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}

		payload["taxIdentifier"], err = mdb.EncryptManual(dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", payload["taxIdentifier"])
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}
	*/

	// test to see if all our fields are encrypted:
	for _, field := range allEncryptedFields {
		if !utils.TestEncrypted(gjson.Get(payload, field)) {
			fmt.Printf("Field %s is not encrypted\n", field)
			exitCode = 1
			return
		}
	}

	result, err = mdb.InsertOne(encryptedDB, encryptedColl, payload)
	if err != nil {
		fmt.Printf("Insert error: %s\n", err)
		exitCode = 1
		return
	}
	fmt.Print(result.InsertedID)

	encryptedName, err = mdb.EncryptManual(dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", "Kuber")
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}
	findResult, err = mdb.FindOne(encryptedDB, encryptedColl, bson.M{"name.firstName": encryptedName})
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

	outputData, err = mdb.DecryptManual(findResult)
	if err != nil {
		fmt.Printf("Encryption error: %s\n", err)
		exitCode = 1
		return
	}
	fmt.Printf("%+v\n", outputData)

	exitCode = 0
}
