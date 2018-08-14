package wso2.com.hsm.util;

import java.io.*;
import java.util.Arrays;

public class FileHandler {
    public static byte[] readFile(String path) throws IOException {
        File file = new File(path);
        InputStream inputStream = new FileInputStream(file);
        byte[] dataBuffer = new byte[1024];
        int bytesRead;
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        while ((bytesRead = inputStream.read(dataBuffer)) >= 0) {
            outputStream.write(dataBuffer, 0, bytesRead);
        }
        Arrays.fill(dataBuffer, (byte) 0);
        outputStream.flush();
        outputStream.close();

        byte[] rawData = outputStream.toByteArray();
        return rawData;
    }

    public static void saveFile(String path, byte[] data) throws IOException {
        File file = new File(path);
        if (!file.exists()) {
            file.getParentFile().mkdirs();
            file.createNewFile();
        }
        FileOutputStream outputStream = new FileOutputStream(file);
        outputStream.write(data);
        outputStream.flush();
        outputStream.close();
    }
}
