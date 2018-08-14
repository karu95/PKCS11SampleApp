package wso2.com.hsm.cryptoprovider.util;


import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;

import java.util.Arrays;
import java.util.HashSet;

public class TokenMechanismTester {
    public static boolean checkMechanism(Token token, long mechanism) {
        boolean supported = false;
        try {
            HashSet supportedMechanisms = new HashSet(Arrays.asList(token.getMechanismList()));
            if (supportedMechanisms.contains(Mechanism.get(mechanism))) {
                supported = true;
            }
        } catch (TokenException e) {
            e.printStackTrace();
        }
        return supported;
    }
}
