package eu.europeana.sitemap.mongo;

import com.github.jkutner.EnvKeyStore;
import com.mongodb.DBCollection;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientOptions;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;

/**
 * Connects to the (production) mongo server to retrieve all records.
 *
 * Created by ymamakis on 11/16/15.
 */
public class MongoProvider {

    private static final Logger LOG = LogManager.getLogger(MongoProvider.class);

    private static final String ENV_CERTIFICATE = "MONGO_CERTIFICATE";
    private static final String FILE_CERTIFICATE = "mongo.crt";

    private MongoClient mongoClient;
    private DBCollection collection;

    /**
     * Setup a new connection to the Mongo database
     * @param mongoHosts
     * @param port
     * @param username
     * @param password
     * @param database
     */
    public MongoProvider(String mongoHosts, String port, String username, String password, String database) {
        SSLContext sslContext = setupKeyStore();

        String[] addresses = mongoHosts.split(",");
        List<ServerAddress> mongoAddresses = new ArrayList<>();
        for (String address : addresses) {
            ServerAddress mongoAddress = new ServerAddress(address, Integer.parseInt(port));
            mongoAddresses.add(mongoAddress);
        }
        if (StringUtils.isNotEmpty(username) && StringUtils.isNotEmpty(password)) {
            MongoClientOptions.Builder mco = MongoClientOptions.builder().sslEnabled(true).socketFactory(sslContext.getSocketFactory());
            MongoCredential credential = MongoCredential.createCredential(username, database, password.toCharArray());
            List<MongoCredential> credentials = new ArrayList<>();
            credentials.add(credential);
            this.mongoClient = new MongoClient(mongoAddresses, credentials, mco.build());
        } else {
            this.mongoClient = new MongoClient(mongoAddresses);
        }
        LOG.info("Connected to Mongo at {} ", mongoAddresses);

        //this.collection = this.mongoClient.getDB(database).getCollection("record");
    }

    private SSLContext setupKeyStore() {
        try {
            readCertificate();
            KeyStore ts = EnvKeyStore.createWithRandomPassword(ENV_CERTIFICATE).keyStore();

            String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
            tmf.init(ts);

            SSLContext sc = SSLContext.getInstance("TLSv1.2");
            sc.init(null, tmf.getTrustManagers(), new SecureRandom());
            return sc;
        }
        catch (KeyManagementException | IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException ex) {
            LOG.error("Error setting up keystore", ex);
        }
        return null;
    }

    /**
     * Check if certificate is set already in environment, if not read it from resource file
     * @throws IOException
     */
    private void readCertificate() throws IOException {
        String certData = System.getenv(ENV_CERTIFICATE);
        if (certData == null || StringUtils.isEmpty(certData)) {
            LOG.info("No certificate data found in environment, trying to read from file...");
            try (InputStream is = this.getClass().getClassLoader().getResourceAsStream(FILE_CERTIFICATE)) {
                certData = IOUtils.toString(is, StandardCharsets.UTF_8);
                Map env = new HashMap();
                env.put(ENV_CERTIFICATE,  certData);
                setEnv(env);
            } catch (Exception e) {
                LOG.error("Error reading certificate file or setting environment variable", e);
            }
        }
    }

    /**
     * Hack to set environment variable
     * @param newenv
     * @throws Exception
     */
    private void setEnv(Map<String, String> newenv) throws ClassNotFoundException, IllegalAccessException, NoSuchFieldException {
        try {
            Class<?> processEnvironmentClass = Class.forName("java.lang.ProcessEnvironment");
            Field theEnvironmentField = processEnvironmentClass.getDeclaredField("theEnvironment");
            theEnvironmentField.setAccessible(true);
            Map<String, String> env = (Map<String, String>) theEnvironmentField.get(null);
            env.putAll(newenv);
            Field theCaseInsensitiveEnvironmentField = processEnvironmentClass.getDeclaredField("theCaseInsensitiveEnvironment");
            theCaseInsensitiveEnvironmentField.setAccessible(true);
            Map<String, String> cienv = (Map<String, String>)     theCaseInsensitiveEnvironmentField.get(null);
            cienv.putAll(newenv);
        } catch (NoSuchFieldException e) {
            Class[] classes = Collections.class.getDeclaredClasses();
            Map<String, String> env = System.getenv();
            for(Class cl : classes) {
                if("java.util.Collections$UnmodifiableMap".equals(cl.getName())) {
                    Field field = cl.getDeclaredField("m");
                    field.setAccessible(true);
                    Object obj = field.get(env);
                    Map<String, String> map = (Map<String, String>) obj;
                    map.clear();
                    map.putAll(newenv);
                }
            }
        }
    }

    /**
     * Close the connection to mongo
     */
    public void close() {
        LOG.info("Shutting down connections to Mongo...");
        mongoClient.close();
    }

    /**
     * @return Retrieve the entire record collection from our mongo database
     */
    public DBCollection getCollection() {
        return collection;
    }
}
