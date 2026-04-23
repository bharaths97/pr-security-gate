import javax.net.ssl.HttpsURLConnection;

public class TrustAllHostnameVerifier {
    public void configure(HttpsURLConnection connection) {
        connection.setHostnameVerifier((hostname, session) -> true);
    }
}
