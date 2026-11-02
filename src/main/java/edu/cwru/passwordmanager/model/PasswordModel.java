package edu.cwru.passwordmanager.model;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

/**
 * @author Noah Lee
 */
public class PasswordModel {
    private ObservableList<Password> passwords = FXCollections.observableArrayList();

    static private File passwordFile = new File("passwords.txt");

    static private String separator = "\t";

    static private String passwordFilePassword = "";
    static private byte [] passwordFileKey;
    static private String keyString;
    static private byte [] passwordFileSalt;
    static private String saltString;

    private static String key = "strawberry";

    private void loadPasswords() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(passwordFile));
            String current = reader.readLine();
            Scanner sc;
            if (saltString == null || keyString == null) {
                sc = new Scanner(current);
                saltString = sc.next();
                passwordFileSalt = saltString.getBytes();
                sc.skip("\t");
                keyString = sc.next();
                passwordFileKey = keyString.getBytes();
                sc.close();
            }
            current = reader.readLine();

            while (current != null) {
                sc = new Scanner(current).useDelimiter("\t");
                String label = sc.next();
                sc.skip("\t");
                String passwordDecrypted = decryptPassword(sc.nextLine());
                passwords.add(new Password(label, passwordDecrypted));
                current = reader.readLine();
                sc.close();
            }

        }
        catch (Exception e) {
            return;
        }
    }

    public PasswordModel() {
        loadPasswords();
    }

    static public boolean passwordFileExists() {
        return passwordFile.exists();
    }

    public static void initializePasswordFile(String password) throws IOException {
        passwordFile.createNewFile();

        String saltString = generateSalt();
        String keyString = generateKey(password, saltString);
        String keyEncrypted = encryptPassword(key, saltString, keyString);

        BufferedWriter writer = new BufferedWriter(new FileWriter(passwordFile));
        writer.write(saltString + separator + keyEncrypted);

        writer.flush();
    }

    static public boolean verifyPassword(String password) {
        passwordFilePassword = password;

        File fPasswords = new File("passwords.txt");
        try {
            BufferedReader reader = new BufferedReader(new FileReader(fPasswords));
            String saltAndKey = reader.readLine();
            reader.close();

            Scanner sc = new Scanner(saltAndKey).useDelimiter("\t");
            String saltString = sc.next();
            sc.skip("\t");
            String keyword = sc.next();
            sc.close();

            String keyString = generateKey(password, saltString);

            String testString = decryptPassword(keyword, saltString, keyString);

            return testString.equals(key);
        }
        catch (Exception e) {
            return false;
        }
    }

    public ObservableList<Password> getPasswords() {
        return passwords;
    }

    public void deletePassword(int index) {
        passwords.remove(index);

        saveFile();
    }

    public void updatePassword(Password password, int index) {
        passwords.set(index, password);

        saveFile();
    }

    public void addPassword(Password password) {
        passwords.add(password);

        saveFile();
    }

    private static String generateSalt() {
        SecureRandom randomSalt = new SecureRandom();
        byte[] salt = new byte[16];
        randomSalt.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private static String generateKey(String password, String saltString) {
        byte[] salt = Base64.getDecoder().decode(saltString);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 600000, 256);

        SecretKeyFactory factory;
        SecretKey privateKey;

        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            privateKey = factory.generateSecret(spec);
            byte[] encoded = privateKey.getEncoded();
            return Base64.getEncoder().encodeToString(encoded);
        } catch (Exception e) {
            return null;
        }
    }

    private String encryptPassword(String password) {
        KeySpec spec = new PBEKeySpec(keyString.toCharArray(), passwordFileSalt, 600000, 256);
        SecretKeyFactory factory;
        SecretKey privateKey;
        SecretKeySpec secretSpec;

        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            privateKey = factory.generateSecret(spec);
            secretSpec = new SecretKeySpec(privateKey.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretSpec);

            byte [] encryptedData = cipher.doFinal(password.getBytes());
            return new String(Base64.getEncoder().encode(encryptedData));
        } catch (Exception e) {
            return null;
        }
    }

    private static String encryptPassword(String password, String saltString, String keyString) {
        byte [] salt = Base64.getDecoder().decode(saltString);
        KeySpec spec = new PBEKeySpec(keyString.toCharArray(), salt, 600000, 256);
        SecretKeyFactory factory;
        SecretKey privateKey;
        SecretKeySpec secretSpec;

        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            privateKey = factory.generateSecret(spec);
            secretSpec = new SecretKeySpec(privateKey.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretSpec);

            byte [] encryptedData = cipher.doFinal(password.getBytes());
            return new String(Base64.getEncoder().encode(encryptedData));
        } catch (Exception e) {
            return null;
        }
    }

    private String decryptPassword(String password) {
        KeySpec spec = new PBEKeySpec(keyString.toCharArray(), passwordFileSalt, 600000, 256);

        SecretKeyFactory factory;
        SecretKey privateKey;
        SecretKeySpec secretSpec;

        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            privateKey = factory.generateSecret(spec);
            secretSpec = new SecretKeySpec(privateKey.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretSpec);

            byte [] encryptedData = Base64.getDecoder().decode(password.getBytes());
            byte [] decryptedData = cipher.doFinal(encryptedData);
            return new String(decryptedData);
        } catch (Exception e) {
            return null;
        }
    }

    private static String decryptPassword(String password, String saltString, String keyString) {
        byte[] salt = Base64.getDecoder().decode(saltString);
        KeySpec spec = new PBEKeySpec(keyString.toCharArray(), salt, 600000, 256);

        SecretKeyFactory factory;
        SecretKey privateKey;
        SecretKeySpec secretSpec;

        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            privateKey = factory.generateSecret(spec);
            secretSpec = new SecretKeySpec(privateKey.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretSpec);

            byte [] encryptedData = Base64.getDecoder().decode(password.getBytes());
            byte [] decryptedData = cipher.doFinal(encryptedData);
            return new String(decryptedData);
        } catch (Exception e) {
            return null;
        }
    }

    private void saveFile() {
        if (saltString == null || keyString == null) {
            try
            {
                Scanner sc = new Scanner(passwordFile);
                saltString = sc.next();
                passwordFileSalt = saltString.getBytes();
                sc.skip("\t");
                keyString = sc.next();
                passwordFileKey = keyString.getBytes();
            }
            catch (Exception e) {

            }
        }

        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(passwordFile));
            writer.write(getSaltAndKey());
            writer.flush();

            for (Password value : passwords) {
                writer.newLine();
                String label = value.getLabel();
                String password = value.getPassword();
                String passwordEncrypted = encryptPassword(password);
                writer.write(label + separator + passwordEncrypted);
                writer.flush();
            }

            writer.close();

        } catch (Exception e) {
            System.out.println(e.getCause());
            System.exit(5);
            return;
        }
    }

    private String getSaltAndKey() {
        return saltString + separator + keyString;
    }
}