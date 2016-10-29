
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.util.Random;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;


/**
 * 
 */

/**
 * @author Donald Acton
 * This example is adapted from Kurose & Ross
 *
 */
public class DNSlookup {


	static final int MIN_PERMITTED_ARGUMENT_COUNT = 2;
	static boolean tracingOn = false;
	static InetAddress rootNameServer;

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		String fqdn;
		DNSResponse response; // Just to force compilation
		int argCount = args.length;

		if (argCount < 2 || argCount > 3) {
			usage();
			return;
		}



		rootNameServer = InetAddress.getByName(args[0]);
		fqdn = args[1];

		if (argCount == 3 && args[2].equals("-t"))
				tracingOn = true;

		// Start adding code here to initiate the lookup

		Random r = new Random();
		int n = r.nextInt(65536);
		int port;
		//System.out.println(n);


		byte[] buf = new byte[31];

		buf[0] = (byte) 18;
		buf[1] = (byte) 52;
		//int value = ((buf[0] & 0xFF) << 8) | (buf[1] & 0xFF);
		//System.out.println(value);
//		buf[2] = (byte) (0 << 7) | (byte) (0 << 4);
		buf[2] = (byte) 1;
		buf[3] = (byte) 0;

		buf[4] = (byte) 0;
		buf[5] = (byte) 1;

		buf[6] = (byte) 0;
		buf[7] = (byte) 0;

		buf[8] = (byte) 0;
		buf[9] = (byte) 0;

		buf[10] = (byte) 0;
		buf[11] = (byte) 0;

		String domain = args[1];
		String[] domainParts = domain.split("\\.");
		System.out.println(args[1] + " has " + domainParts.length + " parts");

		int counter = 12;
		for (int i = 0; i<domainParts.length; i++) {
			System.out.println("Writing: " + domainParts[i]);
			byte[] domainBytes = domainParts[i].getBytes("UTF-8");
			System.out.println(domainBytes.length);

			buf[counter] = (byte) domainBytes.length;

			counter++;

			for (byte b : domainBytes) {
				buf[counter] = b;
				counter++;
			}
		}

		buf[counter] = (byte) 0;

		//A

		counter++;
		buf[counter] = (byte) 0;
		counter++;
		buf[counter] = (byte) 1;

		//IN
		counter++;
		buf[counter] = (byte) 0;
		counter++;
		buf[counter] = (byte) 1;

		System.out.println(counter);
		System.out.println("Sending: " + buf.length + " bytes");
		for (int i =0; i< buf.length; i++) {
			System.out.print("0x" + String.format("%x", buf[i]) + " " );
		}


		DatagramSocket socket = new DatagramSocket();
		InetAddress iAddress = InetAddress.getByName(args[0]);
		DatagramPacket packet = new DatagramPacket(buf, buf.length,iAddress, 53);
		socket.send(packet);

	}

	private static void usage() {
		System.out.println("Usage: java -jar DNSlookup.jar rootDNS name [-t]");
		System.out.println("   where");
		System.out.println("       rootDNS - the IP address (in dotted form) of the root");
		System.out.println("                 DNS server you are to start your search at");
		System.out.println("       name    - fully qualified domain name to lookup");
		System.out.println("       -t      -trace the queries made and responses received");
	}
}

