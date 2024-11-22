package jersey.client.cve.candidate;

import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;

import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.GenericType;
import jakarta.ws.rs.core.MediaType;

/**
 * Jersey client ignores SSL settings e.g. keystore/trustore due to race condition
 * if THREAD_NUMBER >1
 */
public class JerseyCveCandidate
{
  //set THREAD_NUMBER > 1 to reproduce bypassing SSL settings
//  private static int THREAD_NUMBER = 5;
  private static int THREAD_NUMBER = 1;
  
  private static String worksAsDesigned = "\nWorks as designed!\n" 
  + "We got SSLHandshakeExceptions for all requests, "
      + "we doesn't trust google, as defined in truststore.jks ==>OK\n"
      + "(Set THREAD_NUMBER > 1 to bypass SSL restrictions by the race condition in jersey client)";

  private static String doesntWorkAsDesigned = "" + "Doesn't work as designed! " + "Our truststore.jks is ignored by race condition and we trust google :-( ";

  public static void main(String[] args) throws Exception
  {
    ExecutorService executorService4clients = Executors.newFixedThreadPool(THREAD_NUMBER);

    // This SSLContext only trusts certificates defined in the provided truststore.jks
    // Certificates from well-known public authorities (e.g., those used by websites
    // like https://www.google.com/) are not trusted.
    // However, this restriction can be bypassed due to a race condition.
    SSLContext context = SSLContextCreator.createContext();
    final ClientBuilder builder = ClientBuilder.newBuilder().sslContext(context);
    for (int i = 0; i < THREAD_NUMBER; i++)
    {
      executorService4clients.submit(new Runnable()
      {
        @Override
        public void run()
        {
          try
          {
            Client client = builder.build();
            // we need a unique URL for each call
            int randomSuffix = new Random().nextInt();
            String target = "https://www.google.com/search?q=test" + randomSuffix;
            String ret = client.target(target).request(MediaType.TEXT_HTML).get(new GenericType<String>()
            {});
            doesntWorkAsDesigned += "\nGoogle returned: " + ret.substring(0, 80) + "...";
            System.err.println("\n" + doesntWorkAsDesigned + "\n");
            System.exit(1);
          }
          catch (ProcessingException e)
          {
            if (e.getCause() instanceof SSLHandshakeException)
            {
              //SSLHandshakeException is ok, works as designed, 
              //our truststore.jks doesn't trust google
            }
          }
        }
      });
    }
    executorService4clients.awaitTermination(5, TimeUnit.SECONDS);
    System.out.println(worksAsDesigned);
  }
}
