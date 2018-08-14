package wso2.com.hsm.util;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;

import java.util.ArrayList;
import java.util.Arrays;

public class SupportedMechanisms {
    private static ArrayList<ArrayList<Mechanism>> supportedMechanismsForTokens = new ArrayList<ArrayList<Mechanism>>();

    public static boolean isSupportedMechanism(Token token, Mechanism mechanism) throws TokenException {
        boolean supported = false;
        Mechanism[] supportedMechanisms = token.getMechanismList();
        ArrayList<Mechanism> mechanisms = new ArrayList<Mechanism>(Arrays.asList(supportedMechanisms));
        if (mechanisms.contains(mechanism)) {
            supported = true;
        }
        return supported;
    }
}
