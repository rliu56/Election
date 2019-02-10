import javax.crypto.Cipher;
import java.io.*;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSA {
    public static void main(String[] args) {
        new RSA();
    }

    public RSA(){
        String[] names= {"Server", "Alice", "Bob", "John"};
        for (String outFile : names) {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                Key pub = kp.getPublic();
                Key pri = kp.getPrivate();
                byte[] pubKeyBytes = pub.getEncoded();
                byte[] priKeyBytes = pri.getEncoded();

                FileOutputStream out = new FileOutputStream(outFile + ".pb");
                out.write(Base64.getEncoder().encode(pubKeyBytes));
                out.close();

                out = new FileOutputStream(outFile + ".pr");
                out.write(Base64.getEncoder().encode(priKeyBytes));
                out.close();
            } catch (GeneralSecurityException | IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static String sigString = "Signature";
    public static KeyPair getKeyPair(String name) throws GeneralSecurityException, IOException{
        return new KeyPair(getPublicKey(name), getPrivateKey(name));
    }

    public static PublicKey getPublicKey(String name) throws GeneralSecurityException, IOException{

        BufferedReader br = new BufferedReader(new FileReader(name + ".pb"));
        String pubKS = br.readLine();
        br.close();

        byte[] data = Base64.getDecoder().decode(pubKS);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PublicKey pubK = fact.generatePublic(pubSpec);

        return pubK;
    }

    public static PrivateKey getPrivateKey(String name) throws GeneralSecurityException, IOException {

        BufferedReader br = new BufferedReader(new FileReader(name + ".pr"));
        String priKS = br.readLine();
        br.close();

        byte[] data = Base64.getDecoder().decode(priKS);
        PKCS8EncodedKeySpec priSpec = new PKCS8EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PrivateKey priK = fact.generatePrivate(priSpec);

        return priK;
    }

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = rsa.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(decryptCipher.doFinal(bytes));
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes());

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes());

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }
}
