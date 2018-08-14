package wso2.com.hsm.cryptoprovider.operators;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;

public class Cipher {

    public static byte[] encryptAES(Session session, byte[] dataToBeEncrypted,
                                    AESSecretKey encryptionKey, byte[] encryptInitializationVector,
                                    long encryptingMechanism) throws TokenException {
        Mechanism encryptionMechanism = Mechanism.get(encryptingMechanism);
        InitializationVectorParameters encryptInitializationVectorParameters = new InitializationVectorParameters(
                encryptInitializationVector);
        encryptionMechanism.setParameters(encryptInitializationVectorParameters);
        session.encryptInit(encryptionMechanism, encryptionKey);
        byte[] encryptedData = session.encrypt(dataToBeEncrypted);

        System.out.println("Encrypted text :" + new String(encryptedData));
        return encryptedData;
    }

    public static byte[] decryptAES(Session session, byte[] dataToBeDecrypted,
                                    AESSecretKey decryptionKey, long decryptingMechanism,
                                    byte[] decryptionInitializationVector) throws TokenException {
        Mechanism decryptionMechanism = Mechanism.get(decryptingMechanism);
        InitializationVectorParameters decryptInitializationVectorParameters = new InitializationVectorParameters(
                decryptionInitializationVector);
        decryptionMechanism.setParameters(decryptInitializationVectorParameters);
        session.decryptInit(decryptionMechanism, decryptionKey);
        byte[] decryptedData = session.decrypt(dataToBeDecrypted);
        System.out.println("Decrypted data :" + new String(decryptedData));
        return decryptedData;
    }


}
