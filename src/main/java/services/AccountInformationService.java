package services;

import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.ContentType;
import org.apache.http.util.EntityUtils;
import utils.ResponseConverter;

import java.util.HashMap;
import java.util.UUID;

@Slf4j
public class AccountInformationService extends ConnectionService {

    /**
     * { *RESTRICTED}
     * Please look through the relevant documentation on the ING-Dev portal
     */
    private static final String ACCOUNT_INFO_REG_PATH = "{ *RESTRICTED}";
    private static final String EMPTY_PAYLOAD = "";

    public String requestAccountDetails(String customerAccessToken) throws Exception {
        EncodingService clientCredentialsGrantFlow = new EncodingService();
        String timeStamp = clientCredentialsGrantFlow.calculateDate();
        String reqId = UUID.randomUUID().toString();
        String authorizationBearer = ResponseConverter.getAuthorizationBearer(customerAccessToken);

        HttpGet request = new HttpGet(HOST + ACCOUNT_INFO_REG_PATH);

        HashMap<String, String> headers = prepareHeaders(ContentType.APPLICATION_JSON.toString(), EMPTY_PAYLOAD,
                authorizationBearer, timeStamp, reqId);
        headers.put(SIGNATURE_HEADER, clientCredentialsGrantFlow.generateSignatureBody(
                ResponseConverter.getClientId(), HTTP_METHOD_GET, timeStamp, reqId,
                ACCOUNT_INFO_REG_PATH, EMPTY_PAYLOAD));

        log.info("** Receiving account details...");
        HttpResponse response = getRequest(request, headers);
        HttpEntity entity = response.getEntity();
        String responseEntity =  EntityUtils.toString(entity);
        log.debug("** RESPONSE GET: " + response.getStatusLine().getStatusCode());
        log.debug("** RESPONSE GET: \n" + responseEntity);

        return responseEntity;
    }
}
