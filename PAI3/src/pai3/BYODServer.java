//package pai3;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Formatter;
import java.util.Properties;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

//java –Djavax.net.ssl.keyStore=C:\SSLStore –Djavax.net.ssl.keyStorePassword=PAI3PAI3 BYODServer


public class BYODServer {
	private SSLServerSocket serverSocket;
	public double transferencias, NoIntegros;
	BufferedWriter bLogs;
	
	public static void main(String args[]) throws Exception {
		BYODServer server = new BYODServer();
		server.runServer();
	}

	// Constructor del Servidor
	public BYODServer() throws Exception {
		// ServerSocketFactory para construir los ServerSockets
		//ServerSocketFactory socketFactory = (ServerSocketFactory) ServerSocketFactory.getDefault();
		// Creación de un objeto ServerSocket escuchando peticiones en el puerto 7070
		//serverSocket = (ServerSocket) socketFactory.createServerSocket(7070);
		SSLServerSocketFactory socketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		serverSocket = (SSLServerSocket) socketFactory.createServerSocket(7061);
	}

	// Ejecución del servidor para escuchar peticiones de los clientes
	private void runServer() throws IOException, InvalidKeyException, NoSuchAlgorithmException {
		
		while (true) {
			//Properties prop = new Properties();
			//InputStream is = null;
			//try {
				//is = new FileInputStream("file\\configure.txt");
				//prop.load(is);// Espera las peticiones del cliente para comprobar mensaje/MAC
				try {

					System.err.println("Esperando conexiones de clientes...");
					Socket socket = (Socket) serverSocket.accept();
					// Abre un BufferedReader para leer los datos del cliente
					BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
					// Abre un PrintWriter para enviar datos al cliente
					PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
					//Calculamos el nonce
					Integer nonce = (int) (Math.random() * 10000000) + 1;
					output.println("Este es el nonce: "+ nonce);
					output.flush();
					
					
					String mensaje = input.readLine();
					// A continuación habría que calcular el mac del MensajeEnviado que podría ser
					Integer nonce2 =new Integer (input.readLine());
					String macdelMensajeEnviado = input.readLine();
					// mac del MensajeCalculado
					String macdelMensajeCalculado = calculateRFC2104HMAC(mensaje, "qwerty",
							"HmacSHA256");
					
					//Date date = new Date();
					//DateFormat hourdateFormat = new SimpleDateFormat("HH:mm:ss dd/MM/yyyy");
					
					//bLogs = new BufferedWriter(new FileWriter(prop.getProperty("bLogs"),true));
					
					if ((macdelMensajeEnviado.equals(macdelMensajeCalculado))&& nonce.equals(nonce2)) {
						output.println("Mensaje almacenado. ");
						transferencias++;
						//bLogs.write("\r\n ("+hourdateFormat.format(date)+")   El mensaje de la transferencia no ha sufrido modificaciones. KPI: "
							//	+ ((transferencias - NoIntegros) / transferencias) * 100 +" \r\n");
					} else if(!(macdelMensajeEnviado.equals(macdelMensajeCalculado))) {
						output.println("Mensaje no almacenado.");
						transferencias++;
						NoIntegros++;
						//bLogs.write("\r\n ("+hourdateFormat.format(date)+")   El mensaje de la transferencia no es integro, ha sido modificado. KPI: "
							//	+ ((transferencias - NoIntegros) / transferencias) * 100 +" \r\n");
					}else {
						output.println("Mensaje no almacenado.");
						transferencias++;
						NoIntegros++;
						//bLogs.write("\r\n ("+hourdateFormat.format(date)+")   El mensaje de la transferencia no es integro, el nonce no es el mismo que el proporcionado por el servidor. KPI: "
							//	+ ((transferencias - NoIntegros) / transferencias) * 100 +" \r\n");
					}
					//bLogs.close();
					output.close();
					input.close();
					socket.close();
				} catch (IOException ioException) {
					ioException.printStackTrace();
				}
			/*} catch (IOException e) {
				System.out.println(e.toString());
			}*/
		}
	}

	private static String toHexString(byte[] bytes) {
		Formatter formatter = new Formatter();

		for (byte b : bytes) {
			formatter.format("%02x", b);
		}

		return formatter.toString();
	}

	public static String calculateRFC2104HMAC(String data, String key, String algoritmo)
			throws NoSuchAlgorithmException, InvalidKeyException {
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), algoritmo);
		Mac mac = Mac.getInstance(algoritmo);
		mac.init(signingKey);
		return toHexString(mac.doFinal(data.getBytes()));
	}

}
