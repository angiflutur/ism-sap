package exam.january;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

public class Ianuarie2023 {

    public static File cerinta1(String base64HashToFind, String directoryPath) throws NoSuchAlgorithmException, IOException {
        File directory = new File(directoryPath);
        if (!directory.exists() || !directory.isDirectory()) {
            System.out.println("The specified path is not a directory.");
            return null;
        }

        File[] files = directory.listFiles();

        for (File file : files) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            FileInputStream fis = new FileInputStream(file);
            BufferedInputStream bis = new BufferedInputStream(fis);

            byte[] buffer = new byte[8];
            while (true) {
                int noBytes = bis.read(buffer);
                if (noBytes == -1) {
                    break;
                }
                md.update(buffer, 0, noBytes);
            }
            fis.close();

            byte[] hashBytes = md.digest();
            String fileHash = Base64.getEncoder().encodeToString(hashBytes);

            if (fileHash.equals(base64HashToFind)) {
                System.out.println("Found file: " + file.getName());
                return file;
            }
        }
        return null;
    }

    public static void cerinta2(File userFile, String outputFile, byte[] key) throws Exception {
        FileInputStream fis = new FileInputStream(userFile);
        FileOutputStream fos = new FileOutputStream(outputFile);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");

        byte[] IV = new byte[cipher.getBlockSize()];
        IV[10] = (byte) 0xFF;

        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] buffer = new byte[cipher.getBlockSize()];
        while (true) {
            int noBytes = fis.read(buffer);
            if (noBytes == -1) {
                break;
            }
            byte[] output = cipher.update(buffer, 0, noBytes);
            fos.write(output);
        }
        byte[] output = cipher.doFinal();
        fos.write(output);
        fis.close();
        fos.close();
    }

    public static byte[] cerinta3(
            String userPass,
            String algorithm,
            String salt,
            int noIterations,
            int outputSize) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(userPass.toCharArray(),
                salt.getBytes(),
                noIterations,
                outputSize);
        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance(algorithm);
        SecretKey key = pbkdf.generateSecret(pbeKeySpec);

        return key.getEncoded();
    }
    public static boolean verifyPassword(String decryptedPassword, String salt, int iterations, int outputSize, String filePath) throws Exception {
        // Generăm hash-ul pentru parola decriptată cu salt
        byte[] generatedHash = cerinta3(decryptedPassword, "PBKDF2WithHmacSHA1", salt, iterations, outputSize);

        // Citim hash-ul original din fișierul binar
        byte[] storedHash;
        try (FileInputStream fis = new FileInputStream(filePath)) {
            storedHash = fis.readAllBytes();
        }

        // Comparăm hash-ul generat cu cel stocat
        return Arrays.equals(generatedHash, storedHash);
    }
    public static void main(String[] args) throws Exception {
        String base64HashToFind = "pP+QN170gTIZzl/AfxFscko/OnJ3Gb9y1274ZTCpu/c=";
        String directoryPath = "src/main/java/ExamPreparation/january/users2";
        byte[] aesKey = "userfilepass@9]9".getBytes();

        File userFile = cerinta1(base64HashToFind, directoryPath);

        cerinta2(userFile, "src/main/java/ExamPreparation/january/decrypted_password.txt", aesKey);

        // Citirea parolei decriptate
        String decryptedPassword;
        try (FileInputStream fis = new FileInputStream("src/main/java/ExamPreparation/january/decrypted_password.txt")) {
            byte[] bytes = fis.readAllBytes();
            decryptedPassword = new String(bytes).trim();
        }

        System.out.println("Decrypted password: " + decryptedPassword);

        // Generarea hash-ului PBKDF2
        String salt = "ism2021";
        int iterations = 150;
        int outputSize = 20; // 20 bytes = 160 biți

        byte[] hashedPassword = cerinta3(decryptedPassword,
                "PBKDF2WithHmacSHA1",
                salt,
                iterations,
                outputSize);

        // Salvarea hash-ului într-un fișier binar
        String outputFile = "hashed_password.bin";
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(hashedPassword);
        }

        System.out.println("Hashed password saved to " + outputFile);

        boolean isPasswordValid = verifyPassword(decryptedPassword, salt, iterations, outputSize, outputFile);
        if (isPasswordValid) {
            System.out.println("Password verification successful.");
        } else {
            System.out.println("Password verification failed.");
        }
        System.out.println("The end.");
    }
}
