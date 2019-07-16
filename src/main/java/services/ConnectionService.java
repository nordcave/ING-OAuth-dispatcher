package services;

import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContexts;
import utils.FileUtils;

import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.util.HashMap;

import static utils.FileUtils.KEYSTORE_FILEPATH;

/**
 * Request handling method
 */

@Slf4j
public class ConnectionService {

    /**
     * { *RESTRICTED}
     * Please look through the relevant documentation on the ING-Dev portal
     */

    public static final String HOST = "{ *RESTRICTED}";

    // general headers used in HTTP-requests
    public static final String SIGNATURE_HEADER = "SIGNATURE";
    public static final String DIGEST_HEADER = "DIGEST";
    public static final String REQ_HEADER = "{ *RESTRICTED}";
    public static final String TPP_SIGN_CERTIFICATE_HEADER = "{ *RESTRICTED}";
    public static final String HTTP_METHOD_GET = "get";
    public static final String HTTP_METHOD_POST = "post";

    // credentials data for jks-keystore
    public static final char[] CERT_PASSWORD = "{ *RESTRICTED}".toCharArray();
    public static final String KEYSTORE_INSTANCE = "jks";


    // preparing general headers to be injected in requests
    public HashMap<String, String> prepareHeaders(String contentType, String payload,
                                                  String authorization, String timeStamp, String reqId) throws Exception {
        EncodingService clientCredentialsGrantFlow = new EncodingService();
        HashMap<String, String> headers = new HashMap<String, String>();
        headers.put(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.toString());
        headers.put(HttpHeaders.CONTENT_TYPE, contentType);
        headers.put(DIGEST_HEADER, clientCredentialsGrantFlow.calculateDigest(payload));
        headers.put(HttpHeaders.DATE, timeStamp);
        headers.put(REQ_HEADER, reqId);
        headers.put(HttpHeaders.AUTHORIZATION, authorization);

        return headers;
    }

    /**
     * initializing the SSL-context used in flow of obtaining app-token
     *
     * @return SSLContext
     */
    public SSLContext prepareSslContext() {
        SSLContext sslContext = SSLContexts.createDefault();
        try {
            KeyStore identityKeyStore = KeyStore.getInstance(KEYSTORE_INSTANCE);
            FileInputStream identityKeyStoreFile = new FileInputStream(new FileUtils().getFile(KEYSTORE_FILEPATH));
            identityKeyStore.load(identityKeyStoreFile, CERT_PASSWORD);

            sslContext = SSLContexts.custom()
                    // load identity keystore
                    .loadKeyMaterial(identityKeyStore, CERT_PASSWORD)
                    .build();
        } catch (Exception e) {
            log.debug("** SSL-CONTEXT initialization failed", e);
        }
        return sslContext;
    }

    // forming of HTTP-POST
    public HttpResponse postRequest(HttpPost request, HashMap<String, String> headers, String payload) throws IOException {
        // add headers
        headers.entrySet().stream()
                .forEach(header -> request.addHeader(header.getKey(), header.getValue()));
        // add payload
        request.setEntity(new StringEntity(payload));

        SSLContext sslContext = prepareSslContext();
        CloseableHttpClient httpClientBuilder = HttpClientBuilder.create()
                .setSSLContext(sslContext)
                .build();
        HttpResponse response = httpClientBuilder.execute(request);

        return handleResponse(response, request.getURI().getPath());
    }

    // forming of HTTP-GET
    public HttpResponse getRequest(HttpGet request, HashMap<String, String> headers) throws IOException {
        headers.entrySet().stream()
                .forEach(header -> request.addHeader(header.getKey(), header.getValue()));
        CloseableHttpClient httpClientBuilder = HttpClientBuilder.create().build();
        HttpResponse response = httpClientBuilder.execute(request);

        return handleResponse(response, request.getURI().getPath());
    }

    // handling of responses
    private HttpResponse handleResponse(HttpResponse response, String url) {
        if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
            log.info("** '{}' request proceeded successfully ", url);
        } else {
            log.error("** '{}' request failed with {} status code", url, response.getStatusLine().getStatusCode());
        }
        return response;
    }

}
