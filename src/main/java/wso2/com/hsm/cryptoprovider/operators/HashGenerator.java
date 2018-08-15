package wso2.com.hsm.cryptoprovider.operators;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;

import java.math.BigInteger;

public class HashGenerator {
    public static String hash(Session session, byte[] dataToBeHashed, long digestMechanism) throws TokenException {
        String hashValue = null;
        Mechanism hashingMechanism = Mechanism.get(digestMechanism);
        if (hashingMechanism.isDigestMechanism()) {
            session.digestInit(hashingMechanism);
            byte[] digestVal = session.digest(dataToBeHashed);
            hashValue = new BigInteger(1, digestVal).toString(16);
            //System.out.println("Hash value " + hashValue);
        }
        return hashValue;
    }
}
