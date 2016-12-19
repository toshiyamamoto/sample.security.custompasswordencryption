package net.wasdev.sample.cpe;

import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import com.ibm.wsspi.security.crypto.CustomPasswordEncryption;
import com.ibm.wsspi.security.crypto.EncryptedInfo;
import com.ibm.wsspi.security.crypto.PasswordDecryptException;
import com.ibm.wsspi.security.crypto.PasswordEncryptException;

public class CustomEncryptionImpl implements CustomPasswordEncryption {
    // Initialize a byte array for use of creating a secret key.
    private static final byte[] KEY = { 'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 'k', 'e', 'y', '!', '!', '!' };

    // Initialize a byte array for use of creating a initialization vector.
    private static final byte[] IV = { 'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', 'n', ' ', 'i', 'v', '?', '?', '?' };

    /* Get the logger to print the message for use of debugging the code. 
     * The messages from the logger are printed in trace file when the trace for this class is enabled.
     */
    private static final Class<?> CLASS_NAME = CustomEncryptionImpl.class;
    private final static Logger logger = Logger.getLogger(CLASS_NAME.getCanonicalName());

    /**
     * The encrypt operation takes a UTF-8 encoded String in the form of a byte[].
     * The byte[] is generated from String.getBytes("UTF-8").
     * An encrypted byte[] is returned from the implementation in the EncryptedInfo
     * object.  Additionally, a logical key alias is returned in the EncryptedInfo 
     * object which is passed back into the decrypt method to determine which key was
     * used to encrypt this password. The WebSphere Application Server runtime has
     * no knowledge of the algorithm or the key used to encrypt the data.
     *
     * @param byte[]
     * @return com.ibm.wsspi.security.crypto.EncryptedInfo
     * @throws com.ibm.wsspi.security.crypto.PasswordEncryptException
     **/
    @Override
    public EncryptedInfo encrypt(byte[] input) throws PasswordEncryptException {
        if (logger.isLoggable(Level.FINE)) {
            logger.fine("encrypt");
        }
        return new EncryptedInfo(encrypt(KEY, IV, input), null);
    }

    /**
     * The decrypt operation takes the EncryptedInfo object containing a byte[] 
     * and the logical key alias and converts it to the decrypted byte[].  The 
     * WebSphere Application Server runtime converts the byte[] to a String 
     * using new String (byte[], "UTF-8");
     *
     * @param com.ibm.wsspi.security.crypto.EncryptedInfo 
     * @return byte[]
     * @throws com.ibm.wsspi.security.crypto.PasswordDecryptException
     **/
    @Override
    public byte[] decrypt(EncryptedInfo info) throws PasswordDecryptException {
        if (logger.isLoggable(Level.FINE)) {
            logger.fine("decrypt : info : " + info);
        }
        byte[] input = null;
        if (info != null) {
            input = info.getEncryptedBytes();
        }
        return decrypt(KEY, IV, input);
    }

    /**
     * The following is reserved for future use and is currently not 
     * called by the WebSphere Application Server runtime.
     *
     * @param java.util.HashMap
     **/
    @Override
    public void initialize(Map initialization_data) {}

    private static byte[] encrypt(byte[] key, byte[] iv, byte[] input)
                                       throws PasswordEncryptException {
        try {
            // Constructs a secret key from the given byte array with AES algorithm.
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

            // Creates an IvParameterSpec object using the bytes in iv as the initialization vector.
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            /*
             * Use Cipher class for encryption and decryption. Call getInstance method to create
             * a Cipher object and pass the name of the requested transformation.
             * In this example, the transformation is "AES/CBC/PKCS5Padding".
             */
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Initializes the cipher to encryption mode with a secret key and an initialization vector.
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            // Encrypts data.
            return cipher.doFinal(input);
        } catch (Exception e) {
            throw new PasswordEncryptException("Exception is caught", e);
        }
    }

    private static byte[] decrypt(byte[] key, byte[] iv, byte[] input)
                                       throws PasswordDecryptException {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Initializes the cipher to decryption mode with a secret key and an initialization vector.
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

            // Decrypts data.
            return cipher.doFinal(input);
        } catch (Exception e) {
            throw new PasswordDecryptException("Exception is caught", e);
        }
    }
}
