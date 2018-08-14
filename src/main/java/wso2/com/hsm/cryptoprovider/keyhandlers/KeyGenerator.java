package wso2.com.hsm.cryptoprovider.keyhandlers;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.*;
import sun.security.ec.ECParameters;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import wso2.com.hsm.cryptoprovider.util.TokenMechanismTester;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public class KeyGenerator {

    public static boolean generateRSAKeyPair(Session session, long generationMechanism, RSAPrivateKey privateKeyTemplate, RSAPublicKey publicKeyTemplate) throws TokenException {
        boolean generated = false;
        MechanismInfo mechanismInfo = null;
        Mechanism keyPairGenerationMechanism = null;
        if (generationMechanism == PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN) {
            if (TokenMechanismTester.checkMechanism(session.getToken(), PKCS11Constants.CKM_RSA_PKCS)) {
                mechanismInfo = session.getToken().getMechanismInfo(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS));
            }
            keyPairGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
        } else if (generationMechanism == PKCS11Constants.CKM_RSA_X9_31_KEY_PAIR_GEN) {
            if (TokenMechanismTester.checkMechanism(session.getToken(), PKCS11Constants.CKM_RSA_X9_31)) {
                mechanismInfo = session.getToken().getMechanismInfo(Mechanism.get(PKCS11Constants.CKM_RSA_X9_31));
            }
            keyPairGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_X9_31_KEY_PAIR_GEN);
        }
        if ((keyPairGenerationMechanism != null) && (mechanismInfo != null)) {

            privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
            privateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
            privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);

            publicKeyTemplate.getVerify()
                    .setBooleanValue(mechanismInfo.isVerify());
            publicKeyTemplate.getVerifyRecover()
                    .setBooleanValue(mechanismInfo.isVerifyRecover());
            publicKeyTemplate.getEncrypt()
                    .setBooleanValue(mechanismInfo.isEncrypt());
            publicKeyTemplate.getDerive()
                    .setBooleanValue(mechanismInfo.isDerive());
            publicKeyTemplate.getWrap()
                    .setBooleanValue(mechanismInfo.isWrap());

            privateKeyTemplate.getSign()
                    .setBooleanValue(mechanismInfo.isSign());
            privateKeyTemplate.getSignRecover()
                    .setBooleanValue(mechanismInfo.isSignRecover());
            privateKeyTemplate.getDecrypt()
                    .setBooleanValue(mechanismInfo.isDecrypt());
            privateKeyTemplate.getDerive()
                    .setBooleanValue(mechanismInfo.isDerive());
            privateKeyTemplate.getUnwrap()
                    .setBooleanValue(mechanismInfo.isUnwrap());

            session.generateKeyPair(keyPairGenerationMechanism, publicKeyTemplate, privateKeyTemplate);
            generated = true;
        }
        return generated;
    }

    public static void generateAESKey(Session session, AESSecretKey secretKeyTemplate) throws TokenException {
        Mechanism keyMechanism = Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN);
        secretKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);

        session.generateKey(keyMechanism, secretKeyTemplate);
    }

    public static void generateDSAKeyPair(Session session) {

    }

    public static void generateECDSAKeyPair(Session session) throws TokenException {
        Mechanism keyMechanism = Mechanism.get(PKCS11Constants.CKM_EC_KEY_PAIR_GEN);
        MechanismInfo mechanismInfo = session.getToken().getMechanismInfo(Mechanism.get(PKCS11Constants.CKM_ECDSA));
        ECDSAPrivateKey privateKeyTemplate = new ECDSAPrivateKey();
        ECDSAPublicKey publicKeyTemplate = new ECDSAPublicKey();


        ECField ecField = new ECField() {
            public int getFieldSize() {
                return 20;
            }
        };
        EllipticCurve ellipticCurve = new EllipticCurve(ecField, new BigInteger(String.valueOf(100)), new BigInteger(String.valueOf(100)));
        ECPoint ecPoint = new ECPoint(new BigInteger(String.valueOf(150)), new BigInteger(String.valueOf(120)));
        ECParameterSpec parameterSpec = new ECParameterSpec(ellipticCurve, ecPoint, new BigInteger(String.valueOf(130)), 20);
        ECParameters ecParameters = new ECParameters();

        publicKeyTemplate.getVerify()
                .setBooleanValue(mechanismInfo.isVerify());
        publicKeyTemplate.getVerifyRecover()
                .setBooleanValue(mechanismInfo.isVerifyRecover());
        publicKeyTemplate.getEncrypt()
                .setBooleanValue(mechanismInfo.isEncrypt());
        publicKeyTemplate.getDerive()
                .setBooleanValue(mechanismInfo.isDerive());
        publicKeyTemplate.getWrap()
                .setBooleanValue(mechanismInfo.isWrap());

        privateKeyTemplate.getSign()
                .setBooleanValue(mechanismInfo.isSign());
        privateKeyTemplate.getSignRecover()
                .setBooleanValue(mechanismInfo.isSignRecover());
        privateKeyTemplate.getDecrypt()
                .setBooleanValue(mechanismInfo.isDecrypt());
        privateKeyTemplate.getDerive()
                .setBooleanValue(mechanismInfo.isDerive());
        privateKeyTemplate.getUnwrap()
                .setBooleanValue(mechanismInfo.isUnwrap());

        session.generateKeyPair(keyMechanism, publicKeyTemplate, privateKeyTemplate);
    }
}
