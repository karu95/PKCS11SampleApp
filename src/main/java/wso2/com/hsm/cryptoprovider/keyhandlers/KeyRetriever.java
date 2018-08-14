package wso2.com.hsm.cryptoprovider.keyhandlers;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.Object;

public class KeyRetriever {
    public static Object retrieveKey(Session session, Key keyTemplate) throws TokenException {
        Object key = null;
        session.findObjectsInit(keyTemplate);
        Object[] secretKeyArray = session.findObjects(1);
        if (secretKeyArray.length > 0) {
            key = secretKeyArray[0];
        }
        return key;
    }
}
