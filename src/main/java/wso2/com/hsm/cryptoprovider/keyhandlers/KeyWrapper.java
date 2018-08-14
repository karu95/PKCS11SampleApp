package wso2.com.hsm.cryptoprovider.keyhandlers;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;

public class KeyWrapper {
    public static byte[] wrapKey(Session session, Key keyToBeWrapped,
                                 PublicKey wrappingKey, long wrappingMechanism) throws TokenException {
        byte[] wrappedKey = null;
        Mechanism wrapMechanism = Mechanism.get(wrappingMechanism);
        if (wrapMechanism.isWrapUnwrapMechanism()) {
            wrappedKey = session.wrapKey(wrapMechanism, wrappingKey, keyToBeWrapped);
        }
        return wrappedKey;
    }

    public static Key unwrapKey(Session session, byte[] wrappedKey, PrivateKey unwrappingKey,
                                Key wrappedKeyTemplate, long unwrappingMechanism) throws TokenException {
        Key unwrappedKey = null;
        Mechanism wrapMechanism = Mechanism.get(unwrappingMechanism);
        if (wrapMechanism.isWrapUnwrapMechanism()) {
            unwrappedKey = session.unwrapKey(wrapMechanism, unwrappingKey, wrappedKey, wrappedKeyTemplate);
        }
        return unwrappedKey;
    }

}
