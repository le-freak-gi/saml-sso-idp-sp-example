package example.config;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;

public class KeyStoreLocator {

    private static CertificateFactory certificateFactory;
    private static final Logger logger = LoggerFactory.getLogger(KeyStoreLocator.class);
    static {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyStore createKeyStore(String pemPassPhrase) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, pemPassPhrase.toCharArray());
            return keyStore;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void addPrivateKey(KeyStore keyStore, String alias, String privateKey, String certificate, String password)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException,CertificateException {
        String wrappedCert = wrapCert(certificate);
        byte[] decodedKey = Base64.getDecoder().decode(privateKey.getBytes());

        char[] passwordChars = password.toCharArray();
        Certificate cert = certificateFactory.generateCertificate(new ByteArrayInputStream(wrappedCert.getBytes()));
        ArrayList<Certificate> certs = new ArrayList<>();
        certs.add(cert);

        byte[] privateKeyBytes = IOUtils.toByteArray(new ByteArrayInputStream(decodedKey));

        KeySpec ks = new PKCS8EncodedKeySpec(privateKeyBytes);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(ks);
        keyStore.setKeyEntry(alias, rsaPrivateKey, passwordChars, certs.toArray(new Certificate[certs.size()]));
    }

    private static String wrapCert(String certificate) {
    	String wrapCert = "-----BEGIN CERTIFICATE-----\n" + certificate + "\n-----END CERTIFICATE-----";
    	logger.info(wrapCert);
        return wrapCert;
    }

}
