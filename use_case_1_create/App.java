//package manual_complete;

import static com.mongodb.client.model.Filters.eq;
import static com.mongodb.client.model.Filters.and;

import com.github.javafaker.Faker;
import com.mongodb.AutoEncryptionSettings;
import com.mongodb.ClientEncryptionSettings;
import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.MongoNamespace;
import com.mongodb.ServerApi;
import com.mongodb.ServerApiVersion;
import com.mongodb.WriteError;
import com.mongodb.reactivestreams.client.MongoClient;
import com.mongodb.reactivestreams.client.MongoClients;
import com.mongodb.reactivestreams.client.MongoCollection;
import com.mongodb.reactivestreams.client.MongoDatabase;
import com.mongodb.client.model.Projections;
import com.mongodb.client.model.vault.DataKeyOptions;
import com.mongodb.client.model.vault.EncryptOptions;
import com.mongodb.client.result.DeleteResult;
import com.mongodb.client.result.InsertOneResult;
import com.mongodb.reactivestreams.client.vault.ClientEncryption;
import com.mongodb.reactivestreams.client.vault.ClientEncryptions;

import org.bson.BsonBinary;
import org.bson.BsonDocument;
import org.bson.BsonDocumentReader;
import org.bson.BsonString;
import org.bson.BsonValue;
import org.bson.Document;
import org.bson.UuidRepresentation;
import org.bson.codecs.DecoderContext;
import org.bson.codecs.DocumentCodec;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.Random;

import com.mongodb.MongoInterruptedException;
import com.mongodb.MongoTimeoutException;
import com.mongodb.MongoWriteException;

import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 */
public class App {
    static Logger logger = LoggerFactory.getLogger("AsyncApp");
    
    // VALUES IN HERE!
    static String STUDENTNAME = "";
    static String MDB_PASSWORD = "";
    static String APP_USER = "app_user";

    public static Document toDoc(BsonDocument bsonDocument) {
        DocumentCodec codec = new DocumentCodec();
        DecoderContext decoderContext = DecoderContext.builder().build();
        Document doc = codec.decode(new BsonDocumentReader(bsonDocument), decoderContext);
        return doc;
    }
        
    public App() {
    }

    /**
     * Get a configured MongoClient instance.
     * 
     * Note that certificates are set through the JVM trust and key stores.
     * 
     * @param connectionString
     * @param dbTimeout
     * @param useSSL
     * @param autoEncryptionSettings
     * @return
     */
    public MongoClient getMdbClient(String connectionString, int dbTimeout, boolean useSSL, AutoEncryptionSettings autoEncryptionSettings) {

        ConnectionString mdbConnectionString = new ConnectionString(connectionString);
        MongoClientSettings.Builder settingsBuilder = MongoClientSettings.builder()
                .applyConnectionString(mdbConnectionString)
                .serverApi(ServerApi.builder()
                    .version(ServerApiVersion.V1)
                    .build())
                .uuidRepresentation(UuidRepresentation.STANDARD);
        if (autoEncryptionSettings != null) {
            settingsBuilder = settingsBuilder.autoEncryptionSettings(autoEncryptionSettings);
        }

        // NB - using the builder with useSSL=false leads to problems
        if (useSSL) {
            settingsBuilder = settingsBuilder.applyToSslSettings(builder -> builder.enabled(useSSL));
        }

        MongoClientSettings settings = settingsBuilder.build();
        MongoClient mongoClient = MongoClients.create(settings);
        return mongoClient;
    } 

    public MongoClient getMdbClient(String connectionString, int dbTimeout, boolean useSSL) {
        return this.getMdbClient(connectionString, dbTimeout, useSSL, null);
    }

    public ClientEncryption getClientEncryption(String connectionString, MongoNamespace keyvaultNamespace, Map<String, Map<String, Object>> kmsProviders) {
        ClientEncryptionSettings encryptionSettings = ClientEncryptionSettings.builder()
            .keyVaultMongoClientSettings(MongoClientSettings.builder()
                .applyConnectionString(new ConnectionString(connectionString))
                .uuidRepresentation(UuidRepresentation.STANDARD)
                .build())
            .keyVaultNamespace(keyvaultNamespace.getFullName())
            .kmsProviders(kmsProviders)
            .build();
        
        ClientEncryption clientEncryption = ClientEncryptions.create(encryptionSettings);
        return clientEncryption;
    }

    public Document getPayload() {
        Random random = new Random();
        String employeeId = Integer.toString(10000 + random.nextInt(90000));
        Faker faker = new Faker(new Locale("en-AU"));
        String firstName = faker.name().firstName();
        String lastName = faker.name().lastName();

        String rawJsonTemplate = """
{
  "_id": "%s",
  "name": {
    "firstName": "%s",
    "lastName": "%s",
    "otherNames": null,
  },
  "address": {
    "streetAddress": "537 White Hills Rd",
    "suburbCounty": "Evandale",
    "zipPostcode": "7258",
    "stateProvince": "Tasmania",
    "country": "Oz"
  },
  "dob": ISODate("1989-01-01T00:00:00.000Z"),
  "phoneNumber": "+61 400 000 111",
  "salary":  99000.00,
  "taxIdentifier": "103-443-923",
  "role": [
    "IC"
  ]
}
                """;
        // NOTE WE ARE USING THE _id AS OUR keyAltName        
        String rawJson = String.format(rawJsonTemplate, employeeId, firstName, lastName);
        BsonDocument bsonDoc = BsonDocument.parse(rawJson);
        return toDoc(bsonDoc);
    }

    public BsonDocument getSchemaDocument(UUID dekUuid) {
        String schemaJson = """
{
    "bsonType" : "object",
    "encryptMetadata" : {
        "keyId":, // PUT APPROPRIATE CODE OR VARIABLE HERE
        "algorithm" : "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
    },
    "properties" : {
        "name" : {
            "bsonType": "object",
            "properties" : {

                "otherNames" : {
                    "encrypt" : {
                        "bsonType" : "string",
                    }
                }
            }
        },
        "address" : {
            "encrypt" : {
                "bsonType" : "object",
            }
        },
        "dob" : {
            "encrypt" : {
                "bsonType" : "date"
            }
        },
        "phoneNumber" : {
            "encrypt" : {
                "bsonType" : "string"
            }
        },
        "salary" : {
            "encrypt" : {
                "bsonType" : "double"
            }
        },
        "taxIdentifier" : {
            "encrypt" : {
                "bsonType" : "string"
            }
        }
    }
}
        """.formatted(dekUuid, dekUuid);
        BsonDocument schemaBsonDoc = BsonDocument.parse(schemaJson);
        return schemaBsonDoc;
    }

    /**
     * Return a DEK's UUID for a give KeyAltName. Creates a new DEK if the DEK is not found.
     * 
     * Queries a key vault for a particular KeyAltName and returns the UUID of the DEK, if found.
     * If not found, the UUID and Key Provider object and CMK ID are used to create a new DEK
     * 
     * Signature  with employeeId the randomly generated id, provider "kmip", keyId "1"
     */
    public UUID getEmployeeDekUUID(MongoClient client,
            String connectionString,
            Map<String, Map<String, Object>> kmsProvider, 
            String provider, 
            MongoNamespace keyvaultNamespace,
            String altName, 
            String keyId) {

        try (ClientEncryption clientEncryption = this.getClientEncryption(connectionString, keyvaultNamespace, kmsProvider)) {
            // Retrieve the DEK UUID
            // Get the existing key by alt name
            Publisher<BsonDocument> keyPublisher = clientEncryption.getKeyByAltName(altName);
            ObservableSubscriber<BsonDocument> keySubscriber = new OperationSubscriber<BsonDocument>();
            keyPublisher.subscribe(keySubscriber);
            BsonDocument employeeKeyDoc = keySubscriber.first();

            if (employeeKeyDoc == null) {
                // If there's no key for the alt name create it using the master key
                ObservableSubscriber<BsonBinary> newKeySubscriber = new OperationSubscriber<BsonBinary>();
                // PUT CODE HERE TO CREATE THE NEW DEK
                return  bsonKey.asUuid();
            } else {
                UUID employeeKey = toDoc(employeeKeyDoc).get("_id", UUID.class);
                return employeeKey;
            } 
        }
    }

    public static void main( String[] args )
    {
        System.setProperty("javax.net.ssl.keyStore", "./keystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "mongodb");
        System.setProperty("javax.net.ssl.trustStore", "./truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword","mongodb");

        App app = new App();

        // Obviously this should not be hardcoded
        String connectionString = String.format(
            "mongodb://%s:%s@%s02.dbservers.mdbps.internal/?serverSelectionTimeoutMS=5000&tls=true",
            APP_USER, MDB_PASSWORD, STUDENTNAME
        );
  
        // Declare our key vault namespce
        MongoNamespace keyvaultNamespace = new MongoNamespace("__encryption.__keyVault");

        // declare our key provider type
        String provider = "kmip";

        // declare our key provider attributes
        Map<String, Map<String, Object>> kmsProvider = new HashMap<String, Map<String, Object>>();
        Map<String, Object> kmipProviderInstance = new HashMap<String, Object>();
        kmipProviderInstance.put("endpoint", STUDENTNAME + "01.kmipservers.mdbps.internal");
        kmsProvider.put(provider, kmipProviderInstance);

        // declare our database and collection
        String encryptedDbName = "companyData";
        String encryptedCollName = "employee";

        MongoClient client = null;
        ClientEncryption clientEncryption = null;
        try {
            System.out.println("At try.");
            // instantiate our MongoDB Client object
            client = app.getMdbClient(connectionString, 5000, false);

            // Create ClientEncryption instance for creating DEks and manual encryption
            clientEncryption = app.getClientEncryption(connectionString, keyvaultNamespace, kmsProvider);

            Document payload = app.getPayload();

            UUID employeeKeyId = null;
            try {
                employeeKeyId = app.getEmployeeDekUUID(client,
                    connectionString, 
                    kmsProvider, 
                    provider, 
                    keyvaultNamespace, 
                    payload.getString("_id"),
                    "1"
                );
            } catch (Exception eke) {
                logger.error("User DEK missing", eke);
                System.exit(1);
            }


            // Get schema map
            BsonDocument schema = app.getSchemaDocument(employeeKeyId);
            Map<String, BsonDocument> schemaMap = new HashMap<String, BsonDocument>();
            schemaMap.put(encryptedDbName + "." + encryptedCollName, schema);

            // Get auto encryption opps
            Map<String, Object> extraOptions = new HashMap<String, Object>();
            extraOptions.put("mongocryptdBypassSpawn", true);
            extraOptions.put("cryptSharedLibPath", "/lib/mongo_crypt_v1.so");
            extraOptions.put("cryptSharedLibRequired", true);

            AutoEncryptionSettings autoEncryptionSettings = AutoEncryptionSettings.builder()
                .keyVaultNamespace(keyvaultNamespace.getFullName())
                .kmsProviders(kmsProvider)
                .extraOptions(extraOptions)
                .schemaMap(schemaMap)
                .build();

            try (MongoClient secureClient = app.getMdbClient(connectionString, 5000, false, autoEncryptionSettings)) {
                
                MongoDatabase encryptedDb = secureClient.getDatabase(encryptedDbName);
                MongoCollection<Document> encryptedColl = encryptedDb.getCollection(encryptedCollName);

                // TODO - ENCRYPT firstName and lastName here; optionsDeterministic!?
                BsonDocument namePayload = ((Document)payload.get("name")).toBsonDocument();

                for (String key: new String[] { "firstName", "lastName" }) {
                    ObservableSubscriber<BsonValue> encSet = new ConsumerSubscriber<BsonValue>(
                        encVal -> namePayload.put(key, encVal)
                    );
                    clientEncryption.encrypt(namePayload.get(key), optionsDetermistic).subscribe(encSet);
                    encSet.await();
                }

                payload.put("name", toDoc(namePayload));

                // remove `name.otherNames` if null because wwe cannot encrypt null
                if (payload.get("name", Document.class).get("otherNames") == null) {
                    payload.get("name", Document.class).remove("otherNames");
                }

                try {
                    ObservableSubscriber<InsertOneResult> insertSubscriber = new OperationSubscriber<InsertOneResult>();
                    encryptedColl.insertOne(payload).subscribe(insertSubscriber);
                    InsertOneResult inserted = insertSubscriber.first();
                    String insertedId = inserted.getInsertedId().toString();
                    System.out.println(insertedId);
                } catch (MongoWriteException mwe) {
                    WriteError we = mwe.getError();
                    if (we.getCode() == 11000) {
                        System.err.println("Duplicate");
                        System.out.println(payload.get("_id"));
                    } else {
                        System.err.println("Mongo write exception!");
                        mwe.printStackTrace();
                        System.exit(1);
                    }
                } catch (Throwable t) {
                    System.err.println("Error on write!");
                    t.printStackTrace();
                    System.exit(1);
                }

                Object firstname = payload.get("name", Document.class).get("firstName");
                Object lastname = payload.get("name", Document.class).get("lastName");

                ObservableSubscriber<Document> docSubscriber = new OperationSubscriber<Document>();
                encryptedColl.find(and(eq("name.firstName", firstname), eq("name.lastName", lastname)))
                    .subscribe(docSubscriber);
                Document decryptedResult = docSubscriber.first();
                if (decryptedResult != null) {
                    System.out.println(decryptedResult.toJson());
                } else {
                    System.out.println("No document found");
                }

            }

        } catch (Exception bige) {
                System.err.println("Big Error - " + bige.toString());
                bige.printStackTrace();
        } finally {
                if (client != null) {
                        client.close();
                }
                if (clientEncryption != null ) {
                        clientEncryption.close();
                }
        }
    }
 
}

// *** Subscribers *** //
/**
 * A Subscriber that stores the publishers results and provides a latch so can block on completion.
 *
 * @param <T> The publishers result type
 */
abstract class ObservableSubscriber<T> implements Subscriber<T> {
    private final List<T> received;
    private final List<RuntimeException> errors;
    private final CountDownLatch latch;
    private volatile Subscription subscription;

    /**
     * Construct an instance
     */
    public ObservableSubscriber() {
        this(new CountDownLatch(1));
    }

    public ObservableSubscriber(CountDownLatch latch) {
        this.received = new ArrayList<>();
        this.errors = new ArrayList<>();
        this.latch = latch;
    }
    @Override
    public void onSubscribe(final Subscription s) {
        subscription = s;
    }

    @Override
    public void onNext(final T t) {
        received.add(t);
    }

    @Override
    public void onError(final Throwable t) {
        if (t instanceof RuntimeException) {
            errors.add((RuntimeException) t);
        } else {
            errors.add(new RuntimeException("Unexpected exception", t));
        }
        onComplete();
    }

    @Override
    public void onComplete() {
        latch.countDown();
        // System.out.println("Latch count: " + latch.getCount());
    }

    /**
     * Gets the subscription
     *
     * @return the subscription
     */
    public Subscription getSubscription() {
        return subscription;
    }

    /**
     * Get received elements
     *
     * @return the list of received elements
     */
    public List<T> getReceived() {
        return received;
    }

    /**
     * Get error from subscription
     *
     * @return the error, which may be null
     */
    public RuntimeException getError() {
        if (errors.size() > 0) {
            return errors.get(0);
        }
        return null;
    }

    /**
     * Get received elements.
     *
     * @return the list of receive elements
     */
    public List<T> get() {
        return await().getReceived();
    }

    /**
     * Get received elements.
     *
     * @param timeout how long to wait
     * @param unit the time unit
     * @return the list of receive elements
     */
    public List<T> get(final long timeout, final TimeUnit unit) {
        return await(timeout, unit).getReceived();
    }


    /**
     * Get the first received element.
     *
     * @return the first received element
     */
    public T first() {
        List<T> received = await().getReceived();
        return received.size() > 0 ? received.get(0) : null;
    }

    /**
     * Await completion or error
     *
     * @return this
     */
    public ObservableSubscriber<T> await() {
        return await(60, TimeUnit.SECONDS);
    }

    /**
     * Await completion or error
     *
     * @param timeout how long to wait
     * @param unit the time unit
     * @return this
     */
    public ObservableSubscriber<T> await(final long timeout, final TimeUnit unit) {
        subscription.request(Integer.MAX_VALUE);
        try {
            if (!latch.await(timeout, unit)) {
                throw new MongoTimeoutException("Publisher onComplete timed out");
            }
        } catch (InterruptedException e) {
            throw new MongoInterruptedException("Interrupted waiting for observeration", e);
        }
        if (!errors.isEmpty()) {
            throw errors.get(0);
        }
        return this;
    }
}

/**
 * A Subscriber that immediately requests Integer.MAX_VALUE onSubscribe
 *
 * @param <T> The publishers result type
 */
class OperationSubscriber<T> extends ObservableSubscriber<T> {

    public OperationSubscriber() {
        super();
    }

    public OperationSubscriber(CountDownLatch latch) {
        super(latch);
    }

    @Override
    public void onSubscribe(final Subscription s) {
        super.onSubscribe(s);
        s.request(Integer.MAX_VALUE);
    }
}

/**
 * A Subscriber that processes a consumer for each element
 * @param <T> the type of the element
 */
class ConsumerSubscriber<T> extends OperationSubscriber<T> {
    private final Consumer<T> consumer;

    /**
     * Construct a new instance
     * @param consumer the consumer
     */
    public ConsumerSubscriber(final Consumer<T> consumer) {
        this.consumer = consumer;
    }

    public ConsumerSubscriber(final Consumer<T> consumer, CountDownLatch latch) {
        super(latch);
        this.consumer = consumer;
    }

    @Override
    public void onNext(final T document) {
        super.onNext(document);
        consumer.accept(document);
    }
}