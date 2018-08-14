package wso2.com.hsm.util;

import iaik.pkcs.pkcs11.Info;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import wso2.com.hsm.cryptoprovider.keyhandlers.KeyGenerator;
import wso2.com.hsm.cryptoprovider.keyhandlers.KeyRetriever;
import wso2.com.hsm.cryptoprovider.operators.Cipher;
import wso2.com.hsm.cryptoprovider.util.SessionInitiator;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.Scanner;

public class Main {
    private static Module pkcs11Module;
    /*
    @Override
    public void start(Stage primaryStage) throws Exception{
        Parent root = FXMLLoader.load(getClass().getResource("../../resources/views/sample.fxml"));
        primaryStage.setTitle("Hello World");
        primaryStage.setScene(new Scene(root, 300, 275));
        primaryStage.show();
    }
    */

    public static void main(String[] args) throws IOException, TokenException {
        Properties properties = new Properties();
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        InputStream stream = classLoader.getResourceAsStream("properties/pkcs11.properties");
        try {
            properties.load(stream);
        } catch (IOException e) {
            e.printStackTrace();
        }
        pkcs11Module = Module.getInstance(properties.getProperty("library"));
        pkcs11Module.initialize(null);

        Info info = pkcs11Module.getInfo();
        System.out.println(info);

        String initialPromptText = "Available Cryptographic Operations \n" +
                "1. Key Generation \n" +
                "2. Encryption \n" +
                "3. Decryption \n" +
                "4. Sign \n" +
                "5. Verify \n" +
                "6. Key wrap \n" +
                "7. Key unwrap \n" +
                "8. Hash \n" +
                "Enter No. of required operation : ";

        provideOperation(getInput(initialPromptText));
        /*
        Session session = SessionInitiator.initiateSession(pkcs11Module, "12345", 0);
        //System.out.println(session.getSessionInfo());
        //KeyGenerator.generateAESKey(session, "Mevan3", false, false,true,16L);
        //KeyGenerator.generateRSAKeyPair(session, "Sample 2 RSA", PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN, 2048L);


        RSAPublicKey publicKeyTemplate = new RSAPublicKey();
        publicKeyTemplate.getLabel().setCharArrayValue("Public Sample 2 RSA".toCharArray());
        RSAPublicKey publicKey = (RSAPublicKey) KeyRetriever.retrieveKey(session, publicKeyTemplate);
        System.out.println(publicKey.getLabel());
        SessionInitiator.closeSession(0);

        session = SessionInitiator.initiateSession(pkcs11Module, "12345", 0);
        RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue("Private Sample 2 RSA".toCharArray());
        RSAPrivateKey privateKey = (RSAPrivateKey) KeyRetriever.retrieveKey(session, privateKeyTemplate);
        System.out.println(privateKey.getLabel());
        SessionInitiator.closeSession(0);


        session = SessionInitiator.initiateSession(pkcs11Module, "12345", 0);
        AESSecretKey secretKeyTemplate = new AESSecretKey();
        secretKeyTemplate.getLabel().setCharArrayValue("Mevan3".toCharArray());
        AESSecretKey secretKey = (AESSecretKey) KeyRetriever.retrieveKey(session, secretKeyTemplate);
        System.out.println(secretKey.getLabel());

        String hash = HashGenerator.hash(session, FileHandler.readFile("input.txt"), PKCS11Constants.CKM_SHA_1);


        Token token = session.getToken();

        Mechanism[] supportedMechanisms = token.getMechanismList();
        for (int j = 0; j < supportedMechanisms.length; j++) {
            MechanismInfo mechanismInfo = token.getMechanismInfo(supportedMechanisms[j]);
            if ((supportedMechanisms[j].getName().startsWith("CKM_RSA")) && supportedMechanisms[j].isSingleOperationSignVerifyMechanism()) {
                System.out.println("Mechanism Name: " + supportedMechanisms[j].getName());
                System.out.println(mechanismInfo);
                System.out.println("");
            }
        }

        byte[] signature = SignatureHandler.fullSign(session, FileHandler.readFile("input.txt"), PKCS11Constants.CKM_SHA1_RSA_PKCS, privateKey);
        //System.out.println(signature);

        boolean verify = SignatureHandler.fullVerify(session, FileHandler.readFile("input.txt"), signature, PKCS11Constants.CKM_SHA1_RSA_PKCS, publicKey);

        System.out.println(verify);




        /*
        byte[] encryptionInitializationVector = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0};

        byte[] encryptedData = Cipher.encryptAES(session, FileHandler.readFile("input.txt"), secretKey,
                encryptionInitializationVector, PKCS11Constants.CKM_AES_CBC_PAD);

        byte[] decryptedData = Cipher.decryptAES(session, encryptedData, secretKey, PKCS11Constants.CKM_AES_CBC_PAD, encryptionInitializationVector);


        byte[] wrappedKey = KeyWrapper.wrapKey(session, secretKey, publicKey, PKCS11Constants.CKM_RSA_PKCS);

        AESSecretKey unwrappedKey = (AESSecretKey) KeyWrapper.unwrapKey(session, wrappedKey, privateKey, new AESSecretKey(), PKCS11Constants.CKM_RSA_PKCS);
        System.out.println(unwrappedKey);

        System.out.println(SessionInitiator.closeSession(0));




        /*
        Slot[] slots = pkcs11Module.getSlotList(Module.SlotRequirement.ALL_SLOTS);

        for (Slot slot : slots) {
            SlotInfo slotInfo = slot.getSlotInfo();
            System.out.println(slotInfo);
            System.out.println();
        }
        */
        //System.out.println("Slots with token and token information \n");
        /*
        Slot[] slotsWithTokens = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
        Token[] tokens = new Token[slotsWithTokens.length];

        for (int i = 0; i < slotsWithTokens.length; i++) {
            tokens[i] = slotsWithTokens[i].getToken();
            //TokenInfo tokenInfo = tokens[i].getTokenInfo();
            //System.out.println(tokenInfo);
            //System.out.println("");
        }
        */
        /*
            System.out.println("Mechanisms List");
            Mechanism[] supportedMechanisms = tokens[i].getMechanismList();
            for (int j = 0; j < supportedMechanisms.length; j++) {
                System.out.println("Mechanism Name: " + supportedMechanisms[j].getName());
                MechanismInfo mechanismInfo = tokens[i].getMechanismInfo(supportedMechanisms[j]);
                System.out.println(mechanismInfo);
                System.out.println("");
            }
        }
        */
        /*
        Session session = tokens[0].openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RW_SESSION,
                null, null);
        char[] pin = "12345".toCharArray();
        session.login(Session.UserType.USER, pin);

        //KeyGenerator.generateAESKey(slotsWithTokens[0], session, "SampleAES4");
        AESSecretKey secretKeyTemplate = new AESSecretKey();
        secretKeyTemplate.getLabel().setCharArrayValue("SampleAES4".toCharArray());
        session.findObjectsInit(secretKeyTemplate);
        AESSecretKey secretKey = (AESSecretKey) session.findObjects(1)[0];
        //Cipher.encryptAES(session, FileHandler.readFile("input.txt"), secretKey);

        /*

        int limit=0, counter=0;

        session.findObjectsInit(null);
        Object[] objects = session.findObjects(1);
        System.out.println("objects length "+objects.length);

        if (objects.length>0) {
            counter++;
        }

        CertificateFactory x509CertificateFactory = null;
        while (objects.length > 0 && (limit ==0 || limit> counter)) {
            System.out.println("Here");
            Object object = objects[0];
            System.out.println(object.getClass());
            if (object instanceof X509PublicKeyCertificate) {
                System.out.println("X509Public Certificate");
                try {
                    byte[] encodedCertificate = ((X509PublicKeyCertificate) object).getValue()
                            .getByteArrayValue();
                    if (x509CertificateFactory == null) {
                        x509CertificateFactory = CertificateFactory.getInstance("X.509");
                    }
                    Certificate certificate = x509CertificateFactory.generateCertificate(
                            new ByteArrayInputStream(encodedCertificate)
                    );
                    System.out.println("Certificate - ");
                    System.out.println(certificate.toString());
                    System.out.println("\n");
                } catch (Exception ex) {
                    System.out.println(ex);
                }
            } else if (object instanceof X509AttributeCertificate) {
                System.out.println("X509AttributeCertificate");
                try {
                    byte[] encodedCertificate = ((X509AttributeCertificate) object).getValue()
                            .getByteArrayValue();
                    if (x509CertificateFactory == null) {
                        x509CertificateFactory = CertificateFactory.getInstance("X.509");
                    }
                    Certificate certificate = x509CertificateFactory.generateCertificate(
                            new ByteArrayInputStream(encodedCertificate)
                    );
                    System.out.println("Certificate - ");
                    System.out.println(certificate.toString());
                    System.out.println("\n");
                } catch (Exception ex) {
                    System.out.println(ex);
                }
            } else if (object instanceof RSAPublicKey) {
                RSAPublicKey publicKey = (RSAPublicKey) object;
                //System.out.println(publicKey.getPublicExponent());
                System.out.println(publicKey.toString());
            }
            objects = session.findObjects(1);
            counter++;
        }

        session.findObjectsFinal();
        */
    }

    private static void provideOperation(String input) throws TokenException, IOException {
        switch (Integer.valueOf(input)) {
            case 1:
                generateKey();
                break;
            case 2:
                encrypt();
                break;
            case 3:
                decrypt();
                break;
            case 4:
                sign();
                break;
            default:
                System.out.println("Invalid input!");
                break;
        }
    }

    private static void encrypt() throws IOException, TokenException {
        String encryptPrompt = "Select encryption mechanism \n" +
                "1. AES encryption \n" +
                "Enter no. of encryption type : ";
        String input = getInput(encryptPrompt);
        if (input.equals("1")) {
            String pathPrompt = "Path to file to be encrypted = ";
            String path = getInput(pathPrompt);
            String keyLabelPrompt = "Label of the encryption key = ";
            String keyLabel = getInput(keyLabelPrompt);
            Session session = SessionInitiator.initiateSession(pkcs11Module, "12345", 0);
            byte[] dataToEncrypt = FileHandler.readFile(path);
            AESSecretKey secretKeyTemplate = new AESSecretKey();
            secretKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
            AESSecretKey secretKey = (AESSecretKey) KeyRetriever.retrieveKey(session, secretKeyTemplate);
            byte[] initializationVector = new byte[16];
            byte[] encryptedData = Cipher.encryptAES(session, dataToEncrypt, secretKey, initializationVector, PKCS11Constants.CKM_AES_CBC_PAD);
            //FileHandler.saveFile("encrypted/", encryptedData);
            System.out.println("Encrypted text : " + new String(encryptedData));
        } else {
            System.out.println("Invalid input");
        }
    }

    private static void generateKey() throws TokenException {
        String generateKeyPromptText = "Select key type \n" +
                "1. RSA \n" +
                "2. AES \n" +
                "Enter no. of key type : ";
        String input = getInput(generateKeyPromptText);
        if (input.equals("1")) {
            RSAPublicKey publicKeyTemplate = new RSAPublicKey();
            RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
            String templatePromptText = "Provide RSA key pair details as sample given. \n" +
                    "Sample input : label length(1024-2048) \n" +
                    "Input : ";
            byte[] publicExponentBytes = {0x01, 0x00, 0x001};
            publicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
            input = getInput(templatePromptText);
            String[] inputs = input.split(" ");
            if (inputs.length == 2) {
                privateKeyTemplate.getLabel().setCharArrayValue(inputs[0].toCharArray());
                publicKeyTemplate.getLabel().setCharArrayValue(inputs[0].toCharArray());

                publicKeyTemplate.getModulusBits().setLongValue(Long.valueOf(inputs[1]));
                Session session = SessionInitiator.initiateSession(pkcs11Module, "12345", 0);
                boolean generated = KeyGenerator.generateRSAKeyPair(session, PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN, privateKeyTemplate, publicKeyTemplate);
                if (generated) {
                    System.out.println("RSA key pair successfully generated!");
                } else {
                    System.out.println("RSA key pair generation failed!");
                }
                SessionInitiator.closeSession(0);
            }
        } else if (input.equals("2")) {
            AESSecretKey secretKeyTemplate = new AESSecretKey();
            String templatePromptText = "Provide AES key details as sample given. \n" +
                    "Sample input : label length(16-32) \n" +
                    "Input : ";
            secretKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
            secretKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
            secretKeyTemplate.getExtractable().setBooleanValue(Boolean.FALSE);
            input = getInput(templatePromptText);
            String[] inputs = input.split(" ");
            if (inputs.length == 2) {
                secretKeyTemplate.getLabel().setCharArrayValue(inputs[0].toCharArray());
                secretKeyTemplate.getValueLen().setLongValue(new Long(inputs[1]));
                Session session = SessionInitiator.initiateSession(pkcs11Module, "12345", 0);
                boolean generated = KeyGenerator.generateAESKey(session, secretKeyTemplate);
                if (generated) {
                    System.out.println("AES key successfully generated!");
                } else {
                    System.out.println("AES key generation failed!");
                }
                SessionInitiator.closeSession(0);
            }
        } else {
            System.out.println("Invalid input!");
        }
    }

    private static void decrypt() {

    }

    private static void sign() {

    }


    private static String getInput(String promptText) {
        Scanner scanner = new Scanner(System.in);
        System.out.print(promptText);
        System.out.println();

        return scanner.nextLine();
    }
}
