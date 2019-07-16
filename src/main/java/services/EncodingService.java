package services;

import lombok.extern.slf4j.Slf4j;
import utils.FileUtils;

import java.security.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

@Slf4j
public class EncodingService {

    /**
     * Calculates digest by transform payload String -> hexadecimal (using SHA-256) ->  ASCII
     * @param payload string value to encode
     * @return String
     */
    public String calculateDigest(String payload) {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            log.debug("** Digest Exception, ", e);
        }
        byte[] digest = messageDigest.digest(payload.getBytes());
        String encodedDigest = Base64.getEncoder().encodeToString(digest);

        return "SHA-256=" + encodedDigest;
    }

    /**
     * Calculates time stamp in API-suitable format
     * @return String timestamp
     */
    public String calculateDate() {
        DateFormat dateFormat = new SimpleDateFormat("E, dd MMM yyyy HH:mm:ss z", Locale.US);
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        return dateFormat.format(new Date());
    }

    /**
     * Generates Signature Body for HttpHeader injection
     * @param keyId decoded certificate information in format specified by API
     * @param httpMethod defines POST of GET method in request
     * @param timeStamp current time/date information in specified format
     * @param reqId unique ID of app/users request to the API
     * @param reqPath endpoint URL
     * @param payload in different cases: static String or bear AuthCode
     * @return combined String
     * @throws Exception
     */
    public String generateSignatureBody(String keyId, String httpMethod, String timeStamp, String reqId,
                                         String reqPath, String payload) throws Exception {
        String signatureBody = "Signature keyId=\"" + keyId + "\"" +
                        ",algorithm=\"rsa-sha256\"" +
                        ",headers=\"(request-target) date digest x-ing-reqid\"" +
                        ",signature=\"" + toSign(httpMethod, timeStamp, reqId, reqPath, payload) + "\"";

        return signatureBody;
    }

    /**
     * Method to encode StringSignature with SHA-256 generated below
     * algorithms specified in API documentation
     * @return String signature
     */
    private String toSign(String httpMethod, String timeStamp, String reqId, String reqPath, String payload) throws Exception {
        String signature = "";
        try {
            Signature dsa = Signature.getInstance("SHA256withRSA");
            dsa.initSign(new FileUtils().getClientKey());
            dsa.update(generateSigningString(httpMethod, timeStamp, reqId, reqPath, payload).getBytes());
            byte[] out = dsa.sign();
            signature = Base64.getEncoder().encodeToString(out);
        } catch (InvalidKeyException e) {
            log.debug("** Error getting a Signature Object ", e);
        }

        return signature;
    }

    /**
     * Combines unique String that will be encrypted and used in authentication process
     * @return String signingString
     */
    private String generateSigningString(String httpMethod, String timeStamp, String reqId,
                                         String reqPath, String payload) {
        String signingString = "(request-target): " + httpMethod + " " + reqPath +
                "\ndate: " + timeStamp + "\ndigest: " + calculateDigest(payload) +
                "\nx-ing-reqid: " + reqId;

        return signingString;
    }
}
