package wso2.com.hsm.cryptoprovider.operators;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;


public class SignatureHandler {
    public static byte[] fullSign(Session session, byte[] dataToSign, long signMechanism, PrivateKey signKey) throws TokenException {
        byte[] signature = null;
        Mechanism signingMechanism = Mechanism.get(signMechanism);
        if (signingMechanism.isFullSignVerifyMechanism()) {
            System.out.println("Here");
            session.signInit(signingMechanism, signKey);
            signature = session.sign(dataToSign);
            String signatureString = new String(signature);
            System.out.println(signatureString);
        }
        return signature;
    }

    public static boolean fullVerify(Session session, byte[] dataToVerify, byte[] signature, long verifyMechanism, PublicKey verificationKey) {
        boolean verified = false;
        Mechanism verifyingMechanism = Mechanism.get(verifyMechanism);
        if (verifyingMechanism.isFullSignVerifyMechanism()) {
            try {
                session.verifyInit(verifyingMechanism, verificationKey);
                session.verify(dataToVerify, signature);
                verified = true;
            } catch (TokenException e) {
                e.printStackTrace();
            }
        }
        return verified;
    }
}
