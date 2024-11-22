package jersey.client.cve.candidate;

import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Creates and initializes an SSLContext using a custom keystore file. The method reads a keystore.jks file, loads it
 * into memory, and sets up both KeyManagerFactory and TrustManagerFactory to handle authentication and trust
 * validation. It returns an SSLContext configured with these managers. 
 * Note: This SSLContext only trusts certificates defined in the provided keystore. Certificates from well-known public authorities (e.g., those used by websites
 * like https://www.google.com/) are not trusted by this configuration
 * */
class SSLContextCreator
{
  public static SSLContext createContext() throws Exception
  {
    // Load the keystore from a resource file
    URL url = JerseyCveCandidate.class.getResource("truststore.jks");
    KeyStore keyStore = KeyStore.getInstance("JKS");
    try (InputStream is = url.openStream())
    {
      keyStore.load(is, "password".toCharArray());
    }

    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
    kmf.init(keyStore, "password".toCharArray());

    TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
    tmf.init(keyStore);

    SSLContext context = SSLContext.getInstance("TLS");
    context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

    return context;
  }
}
