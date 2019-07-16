package utils;

import com.google.common.io.ByteStreams;
import com.google.common.io.Files;

import java.io.*;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class FileUtils {

    private static final String TPP_CERTIFICATE_FILEPATH = "sandbox_client.cer";
    public static final String KEYSTORE_FILEPATH = "identity.jks";
    // The ClientId provided for the eIDAS certificates and keys in sandbox
    public static final String CLIENT_KEY_FILEPATH = "private_key.der";


    /**
     * Retrieves the Private Key from a file
     *
     * @return PrivateKey
     * @throws Exception
     */
    public PrivateKey getClientKey() throws Exception {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(CLIENT_KEY_FILEPATH);
        byte[] keyBytes = ByteStreams.toByteArray(inputStream);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }


    /**
     * Gets file from classpath, resources folder
     *
     * @param fileName
     * @return
     */
    public File getFile(String fileName) throws IOException {
        InputStream initialStream = getClass().getClassLoader().getResourceAsStream(fileName);
        byte[] buffer = new byte[initialStream.available()];
        initialStream.read(buffer);

        File targetFile = new File(fileName);
        Files.write(buffer, targetFile);
        return targetFile;
    }

    /**
     * Allows usage of TSL-signing in POST-request header
     * during Application Access Token request
     * converts cert to String
     */
    public String readTPPCertificate() {
        StringBuilder sb = new StringBuilder();

        try (FileReader reader = new FileReader(getFile(TPP_CERTIFICATE_FILEPATH));
             BufferedReader br = new BufferedReader(reader)) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
        } catch (IOException e) {
            System.err.format("IOException: %s%n", e);
        }
        return sb.toString();
    }


}
