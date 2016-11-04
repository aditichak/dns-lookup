
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
import java.util.*;


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
	static String rootIP;
	static String orginialFqdn;

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
		rootIP = args[0];
		fqdn = args[1];
		orginialFqdn = args[1];

		if (argCount == 3 && args[2].equals("-t"))
				tracingOn = true;

		// Start adding code here to initiate the lookup

		DNSResponse drep = recurse (fqdn, rootNameServer);
		ArrayList<Map> a = drep.getAnswerRecords();
		Map<String, String> m = a.get(0);
		System.out.println(orginialFqdn + " " +  m.get("ttl") + " " +  m.get("recordValue"));
	}

	private static DNSResponse sendAndReceive(String fqdn, InetAddress rootNameServer) throws Exception{
		byte[] buf = setPacketData(fqdn);
		// Creat a socket and send the packet
		DatagramSocket socket = new DatagramSocket();
		DatagramPacket packet = new DatagramPacket(buf, buf.length,rootNameServer, 53);
		socket.send(packet);

		// wait for response
		byte[] data = new byte[1024];
		DatagramPacket recievedPacket = new DatagramPacket(data, data.length);
		socket.receive(recievedPacket);
		socket.close();
		//System.out.println("\n\nReceived: " + recievedPacket.getLength() + " bytes");

//		for (int i = 0; i < recievedPacket.getLength(); i++) {
//			//System.out.print(" 0x" + String.format("%x", data[i]) + " " );
//		}
		DNSResponse returnedData = new DNSResponse(data, data.length);

		if (tracingOn) {
			printQuery(returnedData, buf[0], buf[1], rootIP, fqdn);
		}

		return returnedData;
	}

	private static DNSResponse recurse (String fqdn, InetAddress ip) throws Exception{
		DNSResponse receivedPacket = sendAndReceive(fqdn, ip);

		while (receivedPacket.getAnswerCount() <=0 ) {
			if (receivedPacket.getAdditionalCount() > 0) {
				ArrayList<Map> a = receivedPacket.getAdditionalRecords();
				Map<String, String> m = a.get(0);
				if (m.get("recordType") == "A") {
					String queryIp = m.get("recordValue");
					InetAddress oip = InetAddress.getByName(queryIp);
					receivedPacket = sendAndReceive(fqdn, oip);
				}
				else {
					//TODO IPV6
				}
			}
			else if (receivedPacket.getNsCount() > 0) {
				ArrayList<Map> a = receivedPacket.getAuthoritativeRecords();
				Map<String, String> m = a.get(0);
				String name = m.get("recordValue");
				receivedPacket = recurse(name, rootNameServer);
				ArrayList<Map> ar = receivedPacket.getAuthoritativeRecords();
				Map<String, String> mr = ar.get(0);
				String rname = mr.get("recordValue");
				InetAddress ippp = InetAddress.getByName(rname);
				receivedPacket = sendAndReceive(fqdn, ippp);
			}
		}

		ArrayList<Map> a = receivedPacket.getAnswerRecords();
		Map<String, String> m = a.get(0);
		if (m.get("recordType") == "CN") {
			return recurse(m.get("recordValue"), rootNameServer);
		}
		else if (m.get("recordType") == "A") {
//			String aIp = m.get("recordValue");
//			InetAddress ipp = InetAddress.getByName(aIp);
			return receivedPacket;
		}
		return null;


	}

	private static void usage() {
		System.out.println("Usage: java -jar DNSlookup.jar rootDNS name [-t]");
		System.out.println("   where");
		System.out.println("       rootDNS - the IP address (in dotted form) of the root");
		System.out.println("                 DNS server you are to start your search at");
		System.out.println("       name    - fully qualified domain name to lookup");
		System.out.println("       -t      -trace the queries made and responses received");
	}

	private static byte[] setPacketData(String fqdn) throws Exception{
		byte[] buf = new byte[18 + fqdn.length()];

		setPacketHeader(buf);
		setPacketQuery(buf, fqdn);

		//System.out.println("Sending: " + buf.length + " bytes");
		for (int i =0; i< buf.length; i++) {
			//System.out.print("0x" + String.format("%x", buf[i]) + " " );
		}

		return buf;
	}


	private static void setPacketHeader(byte[] buf) {

		// The header contains the following fields:

  //                                   1  1  1  1  1  1
  //     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  //   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //   |                      ID                       |
  //   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //   |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
  //   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //   |                    QDCOUNT                    |
  //   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //   |                    ANCOUNT                    |
  //   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //   |                    NSCOUNT                    |
  //   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //   |                    ARCOUNT                    |
  //   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		
		//set ID
		// TODO: randomize this!
		Random r = new Random();
		int random = r.nextInt(65536);

		buf[0] = (byte) ((random >> 8) & 0xff);
		buf[1] = (byte) (random & 0xff);

		// Set QR, Opcode, AA, TC, and RD to 0
		buf[2] = (byte) 0;

		// Set RA, Z and RCODE to 0
		buf[3] = (byte) 0;

		// Set query count to 1
		buf[4] = (byte) 0;
		buf[5] = (byte) 1;

		// Set answer count to 0
		buf[6] = (byte) 0;
		buf[7] = (byte) 0;

		// set NSCount to 0
		buf[8] = (byte) 0;
		buf[9] = (byte) 0;

		// Set AR count to 0
		buf[10] = (byte) 0;
		buf[11] = (byte) 0;
	}

	private static void printQuery(DNSResponse returnedData, byte buf1, byte buf2, String rootName, String fqdn) {
		System.out.print("\n\n");
		System.out.println("Query ID     " + returnedData.bytesToInt(buf1, buf2) + " " + fqdn + " --> " + rootName);
		System.out.println("Response ID: " + returnedData.getQueryId() + " " + "Authoritative " + returnedData.getAuthoritative());
		System.out.println("  Answers " + "(" + returnedData.getAnswerCount() + ")");
		for (Map m : returnedData.getAnswerRecords()) {
			System.out.format("       %-30s %-10s %-4s %s\n", m.get("recordName"), m.get("ttl"), m.get("recordType"), m.get("recordValue"));
		}
		System.out.println("  Nameservers " + "(" + returnedData.getNsCount() + ")");
		for (Map m : returnedData.getAuthoritativeRecords()) {
			System.out.format("       %-30s %-10s %-4s %s\n", m.get("recordName"), m.get("ttl"), m.get("recordType"), m.get("recordValue"));
		}
		System.out.println("  Additional Information " + "(" + returnedData.getAdditionalCount() + ")");
		for (Map m : returnedData.getAdditionalRecords()) {
			System.out.format("       %-30s %-10s %-4s %s\n", m.get("recordName"), m.get("ttl"), m.get("recordType"), m.get("recordValue"));
		}
	}
	private static void setPacketQuery(byte[] buf, String fqdn) throws Exception{
				  //                                   1  1  1  1  1  1
    //   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                                               |
    // /                     QNAME                     /
    // /                                               /
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                     QTYPE                     |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                     QCLASS                    |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

		// write the query fqdn to the packet
		String[] domainParts = fqdn.split("\\.");
		//System.out.println(fqdn + " has " + domainParts.length + " parts");

		// the query section starts at byte 12 of the packet data.
		int counter = 12;
		for (int i = 0; i<domainParts.length; i++) {
			//System.out.println("Writing: " + domainParts[i]);
			byte[] domainBytes = domainParts[i].getBytes("UTF-8");
			//System.out.println(domainBytes.length);

			buf[counter] = (byte) domainBytes.length;

			counter++;

			for (byte b : domainBytes) {
				buf[counter] = b;
				counter++;
			}
		}

		buf[counter] = (byte) 0;

		
		// set Query Type to A
		counter++;
		buf[counter] = (byte) 0;
		counter++;
		buf[counter] = (byte) 1;

		// Set Query class to IN
		counter++;
		buf[counter] = (byte) 0;
		counter++;
		buf[counter] = (byte) 1;
	}
}

