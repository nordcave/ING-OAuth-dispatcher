package services;

import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.util.EntityUtils;
import utils.FileUtils;
import utils.ResponseConverter;

import java.util.HashMap;
import java.util.UUID;

/**
 * Interacting with ING OAuth 2
 */

@Slf4j
public class OAuthService extends ConnectionService {
    /**
     * { *RESTRICTED}
     * Please look through the relevant documentation on the ING-Dev portal
     */
    private static final String OAUTH_REG_PATH = "{ *RESTRICTED}";
    private static final String CONTENT_TYPE_FORM_URLENCODED = "application/x-www-form-urlencoded";
    private static final String APP_ACCESS_PAYLOAD = "grant_type=client_credentials";
    private static final String CUSTOMER_ACCESS_PAYLOAD = "{ *RESTRICTED}";
    private static final String KEY_ID = "{ *RESTRICTED}";

    /**
     * requests the Application Access Token to register application within destination API
     * @return Application Access Token in String format
     * @throws Exception
     */
    public String requestApplicationAccessToken() throws Exception {
        EncodingService clientCredentialsGrantFlow = new EncodingService();
        String timeStamp = clientCredentialsGrantFlow.calculateDate();
        String reqId = UUID.randomUUID().toString();
        String authorizationSignature = clientCredentialsGrantFlow.generateSignatureBody(KEY_ID, HTTP_METHOD_POST,
                timeStamp, reqId, OAUTH_REG_PATH, APP_ACCESS_PAYLOAD);

        HttpPost request = new HttpPost(HOST + OAUTH_REG_PATH);

        HashMap<String, String> headers = prepareHeaders(CONTENT_TYPE_FORM_URLENCODED, APP_ACCESS_PAYLOAD,
                authorizationSignature, timeStamp, reqId);
        headers.put(TPP_SIGN_CERTIFICATE_HEADER, new FileUtils().readTPPCertificate());

        HttpResponse response = postRequest(request, headers, APP_ACCESS_PAYLOAD);

        HttpEntity entity = response.getEntity();
        new ResponseConverter(entity);
        log.debug("** RESPONSE CODE: " + response.getStatusLine().getStatusCode());
        log.debug("** APPLICATION ACCESS TOKEN: " + ResponseConverter.getToken());

        return ResponseConverter.getToken();
    }

    /**
     * Once ApplicationAccessToken is received app can request Customer Access Token
     * to grant access permission for current user.
     *
     * @param appAccessToken receiving in previous method
     * @return  Customer Access Token
     * @throws Exception
     */
    public String requestCustomerAccessToken(String appAccessToken) throws Exception {
        EncodingService clientCredentialsGrantFlow = new EncodingService();
        String timeStamp = clientCredentialsGrantFlow.calculateDate();
        String reqId = UUID.randomUUID().toString();
        String authorizationBearer = ResponseConverter.getAuthorizationBearer(appAccessToken);

        HttpPost request = new HttpPost(HOST + OAUTH_REG_PATH);

        HashMap<String, String> headers = prepareHeaders(CONTENT_TYPE_FORM_URLENCODED, CUSTOMER_ACCESS_PAYLOAD,
                authorizationBearer, timeStamp, reqId);
        headers.put(SIGNATURE_HEADER, clientCredentialsGrantFlow.generateSignatureBody(
                ResponseConverter.getClientId(), HTTP_METHOD_POST, timeStamp, reqId,
                OAUTH_REG_PATH, CUSTOMER_ACCESS_PAYLOAD));

        HttpResponse response = postRequest(request, headers, CUSTOMER_ACCESS_PAYLOAD);
        HttpEntity entity = response.getEntity();
        String responseEntity = EntityUtils.toString(entity);
        log.debug("** CUSTOMER RESPONSE CODE: " + response.getStatusLine().getStatusCode());
        log.debug("** CUSTOMER TOKEN: " + responseEntity);
        return ResponseConverter.getToken(responseEntity);
    }

}
