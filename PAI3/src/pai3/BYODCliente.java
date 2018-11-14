//package pai3;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import java.util.Scanner;

import javax.crypto.Mac;


import javax.crypto.spec.SecretKeySpec;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.JOptionPane;

//java –Djavax.net.ssl.trustStore=C:\SSLStore –Djavax.net.ssl.trustStorePassword=PAI3PAI3 BYODCliente

public class BYODCliente {
	// Constructor que abre una conexión Socket para enviar mensaje/MAC al servidor
	public static void main(String args[]) throws InvalidKeyException, NoSuchAlgorithmException {
		new BYODCliente();
	}

	public BYODCliente() throws InvalidKeyException, NoSuchAlgorithmException {
		// ejecución del cliente de verificación de la integridad
		String algoritmo = "HmacSHA256";
		try {
			//SocketFactory socketFactory = (SocketFactory) SocketFactory.getDefault();
			//Socket socket = (Socket) socketFactory.createSocket("localhost", 7070);
			SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket socket = (SSLSocket) socketFactory.createSocket("localhost", 7061);
			
			// Crea un PrintWriter para enviar mensaje/MAC al servidor
			PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
			// Crea un objeto BufferedReader para leer la respuesta del servidor
			BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			//Recibimos el nonce
			String nonce = input.readLine();
			JOptionPane.showMessageDialog(null, nonce);
			
			
			String mensaje = JOptionPane.showInputDialog(null, "Introduzca su mensaje:");
			// Envío del mensaje al servidor
			output.println(mensaje);
			// Habría que calcular el correspondiente MAC con la clave compartida por
			String nonce2 = JOptionPane.showInputDialog(null, "Introduzca su nonce:");
			// Envío del mensaje al servidor
			output.println(nonce2);
			// Habría que calcular el correspondiente MAC con la clave compartida por
			String clave = JOptionPane.showInputDialog(null, "Introduzca su clave:");
			
			String macdelMensaje = calculateRFC2104HMAC(mensaje, clave, algoritmo);

			// servidor/cliente
			output.println(macdelMensaje);
			// Importante para que el mensaje se envíe
			output.flush();

			// Lee la respuesta del servidor
			String respuesta = input.readLine();
			// Muestra la respuesta al cliente
			JOptionPane.showMessageDialog(null, respuesta);
			// Se cierra la conexion
			
			output.close();
			input.close();
			socket.close();
		} // end try
		catch (IOException ioException) {
			ioException.printStackTrace();
		}
		// Salida de la aplicacion
		finally {
			System.exit(0);
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
