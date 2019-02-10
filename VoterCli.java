import java.io.*;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;

public class VoterCli {
    private DataInputStream in;
    private DataOutputStream out;
    private KeyPair myKeyPair;
    private PublicKey serPubKey;

    public VoterCli(String domainName, String portNum) {
        try {
            Socket socket = new Socket(domainName, Integer.valueOf(portNum));
            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            String name, vnumber, inStr, outStr;

            System.out.println("\n====================================================================");
            System.out.printf("  Enter your name:\n    ");
            name = br.readLine();
            System.out.printf("  Enter your registration number:\n    ");
            vnumber = br.readLine();
            System.out.println("\n  \tName: " + name + ", registration number: " + vnumber + ". Logging in...");

            try {
                serPubKey = RSA.getPublicKey("Server");
                myKeyPair = RSA.getKeyPair(name);
            }catch (GeneralSecurityException | IOException e){
                e.printStackTrace();
                System.err.println("  >> Error:you don't have keys of this name <<");
                out.writeUTF(" ");
                return;
            }

            outStr = RSA.encrypt(name + ' '+ vnumber, serPubKey);
            outStr = outStr + ' ' + RSA.sign(RSA.sigString, myKeyPair.getPrivate());
            out.writeUTF(outStr);

            inStr = in.readUTF();
            if (inStr.equals("0")) {
                System.out.println("  >> Error: incorrect name or vnumber <<");
                return;
            }

            while (true) {
                System.out.println("\n====================================================================");
                System.out.println("\n   Welcome, " + name);
                System.out.println("      Main Menu");
                System.out.println("  Please enter a number (1-4)");
                System.out.println("  1. Vote");
                System.out.println("  2. My vote history");
                System.out.println("  3. Election result");
                System.out.printf("  4. Quit\n\n    ");
                outStr = br.readLine();

                if (outStr.equals("4")) {
                    out.writeUTF("4");
                    return;
                } else if (!outStr.equals("1") && !outStr.equals("2") && !outStr.equals("3")) {
                    out.writeUTF("0");
                    continue;
                } else
                    out.writeUTF(outStr);

                char c = outStr.charAt(0);
                switch (c) {
                    case '1':
                        inStr = in.readUTF();
                        if (inStr.equals("0")) {
                            System.out.println("\n  >> You have already voted <<");
                            continue;
                        }

                        System.out.println("  -Please enter a number (1-2)");
                        System.out.println("    1. Tim");
                        System.out.printf("    2. Linda\n    ");

                        outStr = br.readLine();
                        if (!outStr.equals("1") && !outStr.equals("2")) {
                            System.out.println("\n  >> Vote failed <<");
                            out.writeUTF("0");
                        }else {
                            outStr = RSA.encrypt(outStr, serPubKey);
                            out.writeUTF(outStr);
                        }
                        inStr = in.readUTF();
                        if (inStr.equals("0"))
                            System.out.println("\n  >> You have already voted <<");
                        else
                            System.out.println("\n  >> Vote succeeded! Your selection is: " + inStr + " <<");
                        continue;

                    case '2':
                        inStr = in.readUTF();
                        if (!inStr.equals(" "))
                            System.out.println(inStr);
                        else
                            System.out.println("\n >> You haven't voted yet <<");
                        continue;

                    case '3':
                        inStr = in.readUTF();
                        if (inStr.equals("0")) {
                            System.out.println("\n  >> Result is not available now <<");
                            continue;
                        }
                        System.out.println(inStr);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new VoterCli(args[0], args[1]);
    }
}
