package utils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import model.Account;
import org.apache.http.HttpEntity;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import java.io.IOException;
import java.util.List;

/**
 *  unwrapping responses to obtain usable tokens and required Account Information
 */

public class ResponseConverter {

    public ResponseConverter(HttpEntity entity) throws IOException {
        this.appAccessResponseRaw = EntityUtils.toString(entity);
    }

    public static String appAccessResponseRaw;

    public static String getToken() {
        return getToken(appAccessResponseRaw);
    }

    public static String getToken(String response) {
        JSONObject jsonObject = new JSONObject(response);
        return jsonObject.getString("access_token");
    }

    public static String getClientId() {
        JSONObject jsonObject = new JSONObject(appAccessResponseRaw);
        return jsonObject.getString("client_id");
    }
    public static String getExpirationTime() {
        JSONObject jsonObject = new JSONObject(appAccessResponseRaw);
        return jsonObject.getString("expires_in");
    }

    public static Object getAccounts(String response) {
        JSONObject jsonObject = new JSONObject(response);
        return jsonObject.get("accounts");
    }

    public static String getAuthorizationBearer(String token) {
        return "Bearer " + token;
    }

    /**
     * Converts String response into the List of Accounts
     * @param responseEntity of account information endpoint
     * @return list of Accounts
     */
    public static List<Account> getAccountsList(String responseEntity) {
        String accountsJson = ResponseConverter.getAccounts(responseEntity).toString();
        List<Account> accounts = null;
        ObjectMapper mapper = new ObjectMapper();
        try {
            accounts = mapper.readValue(accountsJson, new TypeReference<List<Account>>(){});
        } catch (IOException e) {
            e.printStackTrace();
        }

        return accounts;
    }
}
