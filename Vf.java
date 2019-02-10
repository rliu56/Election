import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Vf {
    private HashMap<String, String> voterinfo = new HashMap<>();
    private HashMap<String, Integer> result = new HashMap<>();
    private HashMap<String, Date> history = new HashMap<>();
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private KeyPair serKeyPair;
    private HashMap<String, PublicKey> pubKeyStore = new HashMap<>();

    public Vf(String portNum) {

        try {
            ServerSocket serverSocket = new ServerSocket(Integer.valueOf(portNum));
            System.out.println("\t> Server started at " + new Date() + "<");

            serKeyPair = RSA.getKeyPair("Server");
            pubKeyStore.put("Bob", RSA.getPublicKey("Bob"));
            pubKeyStore.put("Alice", RSA.getPublicKey("Alice"));
            pubKeyStore.put("John", RSA.getPublicKey("John"));

            System.out.println("voterinfo:");
            String line;
            BufferedReader bufR = new BufferedReader(new FileReader("voterinfo"));
            while ((line = bufR.readLine()) != null) {
                String splited[] = line.split(" ");
                voterinfo.put(splited[0], splited[1]);
                System.out.println(splited[0] + '\t' +splited[1]);
            }
            System.out.println("---------------------------------------------------------------------");

            result.put("Tim", 0);
            result.put("Linda", 0);
            BufferedWriter bufW = new BufferedWriter(new FileWriter("result"));
            writeRes(bufW);
            bufW.close();
            bufW = new BufferedWriter(new FileWriter("history"));
            bufW.close();

            while (true) {
                Socket socket = serverSocket.accept();
                CliThread cliThread = new CliThread(socket);
                cliThread.start();
            }
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new Vf(args[0]);
    }

    public void writeRes(BufferedWriter bW) {
        for (String key : result.keySet()) {
            try {
                bW.write(key + " \t<" + result.get(key) + ">\n");
                bW.flush();
            }catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    class CliThread extends Thread {
        private Socket socket;

        public CliThread(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                String name, vnumber, inStr, dSig;

                inStr = in.readUTF();
                try {
                    String decyptedStr[] = inStr.split(" ");
                    inStr = RSA.decrypt(decyptedStr[0], serKeyPair.getPrivate());

                    dSig = decyptedStr[1];

                    String nameVnumber[] = inStr.split(" ");
                    name = nameVnumber[0];
                    vnumber = nameVnumber[1];
                }catch (Exception e) {
                    out.writeUTF("0");
                    return;
                }

                if (!RSA.verify(RSA.sigString, dSig, pubKeyStore.get(name))) {
                    out.writeUTF("0");
                    return;
                }else if (!voterinfo.containsKey(name)) {
                    out.writeUTF("0");
                    return;
                }else if(!voterinfo.get(name).equals(vnumber)) {
                    out.writeUTF("0");
                    return;
                }else
                    out.writeUTF("1");
                System.out.println("  " + name + ": connected");

                while (true) {
                    inStr = in.readUTF();
                    if (inStr.equals("4")) {
                        System.out.println("  " + name + ": disconnected");
                        in.close();
                        out.close();
                        return;
                    }
                    else if (inStr.equals("0")) continue;

                    char c = inStr.charAt(0);
                    switch (c) {
                        case '1':
                            System.out.println("  " + name + ": 1. Vote");
                            Date hisEntryDate;
                            lock.readLock().lock();
                                hisEntryDate = history.get(vnumber);
                            lock.readLock().unlock();
                            if (hisEntryDate != null) {
                                System.out.println("  -" + name + ": has already voted");
                                out.writeUTF("0");
                                continue;
                            } else
                                out.writeUTF("1");

                            inStr = in.readUTF();
                            inStr = RSA.decrypt(inStr, serKeyPair.getPrivate());
                            if (!inStr.equals("1") && !inStr.equals("2")) {
                                System.out.println("  -" + name + ": voting failed");
                            }else {
                                lock.readLock().lock();
                                    hisEntryDate = history.get(vnumber);
                                lock.readLock().unlock();
                                if (hisEntryDate != null) {
                                    System.out.println("  --" + name + ": has already voted");
                                    out.writeUTF("0");
                                    continue;
                                }
                                if (inStr.equals("1")) {
                                    System.out.println("  -" + name + ": voted <1> Tim");
                                    lock.writeLock().lock();
                                        result.put("Tim", result.get("Tim") + 1);
                                        history.put(vnumber, new Date());
                                        BufferedWriter bWHis = new BufferedWriter(new FileWriter("history", true));
                                        bWHis.write('<' + vnumber + "> <" + history.get(vnumber) + ">\n");
                                        bWHis.flush();
                                    lock.writeLock().unlock();
                                    out.writeUTF("1");
                                }else {
                                    System.out.println("  -" + name + ": voted <2> Linda");
                                    lock.writeLock().lock();
                                        result.put("Linda", result.get("Linda") + 1);
                                        history.put(vnumber, new Date());
                                        BufferedWriter bWHis = new BufferedWriter(new FileWriter("history", true));
                                        bWHis.write('<' + vnumber + "> <" + history.get(vnumber) + ">\n");
                                        bWHis.flush();
                                    lock.writeLock().unlock();
                                    out.writeUTF("1");
                                }
                            }
                            lock.writeLock().lock();
                                BufferedWriter bWRes = new BufferedWriter(new FileWriter("result"));
                                writeRes(bWRes);
                            lock.writeLock().unlock();
                            continue;

                        case '2':
                            System.out.println("  " + name + ": 2. History");
                            String his = null;
                            lock.readLock().lock();
                                for (String key : history.keySet()) {
                                    if (key.equals(vnumber))
                                        his = key + '\t' + history.get(key);
                                }
                            lock.readLock().unlock();
                            if (his != null)
                                out.writeUTF("\n  " + his);
                            else
                                out.writeUTF(" ");
                            continue;
                        case '3':
                            System.out.println("  " + name + ": 3. Result");
                            int totalVote = 0;
                            lock.readLock().lock();
                                for (String key : result.keySet())
                                    totalVote += result.get(key);
                            lock.readLock().unlock();
                            if (totalVote != 3) {
                                out.writeUTF("0");
                                System.out.println("  -" + name + ": checking pending result");
                                continue;
                            }
                            String winner;
                            lock.readLock().lock();
                                int timVotes = result.get("Tim");
                                int lindaVotes = result.get("Linda");
                            lock.readLock().unlock();
                            if (timVotes > lindaVotes)
                                winner = "<Tim> Win";
                            else
                                winner = "<Linda> Win";
                            out.writeUTF("\n  " + winner + "\n" + "  Tim\t<" + result.get("Tim") + ">\n  Linda\t<" + result.get("Linda") + '>');
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
                return;
            }
        }
    }

}
