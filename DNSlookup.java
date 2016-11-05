
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.util.Random;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.net.SocketTimeoutException;
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
	static int minttl = Integer.MAX_VALUE;
	static int queryNum = 0;
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
		try {
			rootNameServer = InetAddress.getByName(args[0]);
			rootIP = args[0];
			fqdn = args[1];
			orginialFqdn = args[1];
		} catch (UnknownHostException e) {
			usage();
			return;
		}

		if (argCount == 3 && args[2].equals("-t"))
			tracingOn = true;
		try {
			response = recurse (fqdn, rootNameServer);
			ArrayList<Map> answers = response.getAnswerRecords();
			for (Map answer : answers) {
				System.out.println(orginialFqdn + " " + answer.get("ttl") + " " + answer.get("recordValue"));
			}
		} catch (Exception ex) {
				System.out.println(orginialFqdn + " -4 " + "0.0.0.0");
				System.exit(0);
		}
	}

	private static DNSResponse sendAndReceive(String fqdn, InetAddress rootNameServer) {
		if (queryNum > 30) {
			System.out.println(orginialFqdn + " -3 " + "0.0.0.0");
			System.exit(0);
		}
		queryNum++;
		byte[] buf; 
		byte[] data = new byte[1024];
		DNSResponse returnedData = null;
		for (int i = 0; i < 2; i++) {
			try {
				buf = setPacketData(fqdn);
				
				
				// Creat a socket and send the packet
				DatagramSocket socket = new DatagramSocket();
				DatagramPacket packet = new DatagramPacket(buf, buf.length, rootNameServer, 53);
				socket.setSoTimeout(5000);
				socket.send(packet);

				// wait for response
				DatagramPacket recievedPacket = new DatagramPacket(data, data.length);
				socket.receive(recievedPacket);
				returnedData = new DNSResponse(data, data.length);
				while (!returnedData.checkQueryId(buf[0], buf[1])) {
					socket.receive(recievedPacket);
					returnedData = new DNSResponse(data, data.length);
				}

				socket.close();
				if (tracingOn) {
					String rootname = rootNameServer.getHostAddress();
					printQuery(returnedData, buf[0], buf[1], rootname, fqdn);
				}
				break;
			// there is an error with the DNSResponse, check the rcode and print the appropriate message
			} catch (DNSResponseException exception) {	 
				if(exception.getMessage().equals("3")){
					System.out.println(orginialFqdn + " -1 " + "0.0.0.0");
				} else {
					System.out.println(orginialFqdn + " -4 " + "0.0.0.0");
				}
				System.exit(0);

			// if we don't recieve a response resend the packet once, the second time you don't recive a
				// print an error message and exit
			} catch (SocketTimeoutException e) {
				if (i == 1) {
					System.out.println(orginialFqdn + " -2 " + "0.0.0.0");
					System.exit(0);
				}
				else {
					continue;
				}
			} catch (Exception ex) {
				System.out.println(orginialFqdn + " -4 " + "0.0.0.0");
				System.exit(0);
			}
		}

		
		checkForErrors(returnedData);
		return returnedData;
	}


	private static void checkForErrors(DNSResponse receivedPacket) {
		int rcode = receivedPacket.getResponseCode();
		if (rcode == 3) {
			System.out.println(orginialFqdn + " -1 " + "0.0.0.0");
			System.exit(0);
		}
		else if (rcode != 0) {
			System.out.println(orginialFqdn + " -4 " + "0.0.0.0");
			System.exit(0);
		}
	}

	private static DNSResponse recurse (String fqdn, InetAddress ip) throws Exception {
		DNSResponse receivedPacket = sendAndReceive(fqdn, ip);
		while (receivedPacket.getAnswerCount() <=0 ) {
			if (receivedPacket.getAdditionalCount() > 0 && receivedPacket.getNsCount() > 0) {
				ArrayList<Map> authoritativeRecords = receivedPacket.getAuthoritativeRecords();
				ArrayList<Map> additionalRecords = receivedPacket.getAdditionalRecords();
				boolean stop = false;
				for (Map<String, String> authRecord : authoritativeRecords) {
					if (authRecord.get("recordType") != "NS") {
						continue;
					}
					String nameserver = authRecord.get("recordValue").trim();
					for (Map<String, String> additionalRecord : additionalRecords) {
						String additionalName = additionalRecord.get("recordName").trim();
						if (nameserver.equals(additionalName) && additionalRecord.get("recordType") == "A") {
							InetAddress queryIp = InetAddress.getByName(additionalRecord.get("recordValue").trim());
							receivedPacket = sendAndReceive(fqdn, queryIp);
							stop = true;
							break;
						}
					}
					if (stop) {
						// found a nameserver to query so stop iterating
						break;
					}
				}
			}
			else if (receivedPacket.getNsCount() > 0) {
				// if there are authoratative nameservers but no additional information,
				// look up the name server
				ArrayList<Map> authoritativeRecords = receivedPacket.getAuthoritativeRecords();
				Map<String, String> authoritativeRecord = authoritativeRecords.get(0);
				int i = 0;
				// get an authoratitive record of type NS
				while (authoritativeRecord.get("recordType") != "NS" && i < receivedPacket.getNsCount()) {
					authoritativeRecord = authoritativeRecords.get(i);
					i++;
				}
				// if there are no nameservers with type NS, return an error
				if (i == receivedPacket.getNsCount() ) {
					System.out.println(orginialFqdn + " -4 " + "0.0.0.0");
					System.exit(0);
				}
				String name = authoritativeRecord.get("recordValue");
				// look up the ip of the nameserver
				DNSResponse nameserverPacket = recurse(name, rootNameServer);
				ArrayList<Map> answerRecords = nameserverPacket.getAnswerRecords();
				Map<String, String> nameServerAnswer = answerRecords.get(0);
				InetAddress queryIp = InetAddress.getByName(nameServerAnswer.get("recordValue"));
				// look up the original fqdn with the authoritative name servers IP
				receivedPacket = sendAndReceive(fqdn, queryIp);
			}
		}
		ArrayList<Map> answerRecords = receivedPacket.getAnswerRecords();
		Map<String, String> answerRecord = answerRecords.get(0);
		if (answerRecord.get("recordType") == "CN") {
			if (Integer.parseInt(answerRecord.get("ttl")) < minttl) {
				minttl = Integer.parseInt(answerRecord.get("ttl"));
			}
			return recurse(answerRecord.get("recordValue"), rootNameServer);
		}
		else if (answerRecord.get("recordType") == "A") {
			if (Integer.parseInt(answerRecord.get("ttl")) > minttl) {
				answerRecord.put("ttl", Integer.toString(minttl));
			}
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

	private static void printRecords(ArrayList<Map> records) {
		for (Map<String,String> record : records) {
			String recordValue = record.get("recordValue");
			if (recordValue == "") {
				recordValue = "----";
			}
			System.out.format("       %-30s %-10s %-4s %s\n", record.get("recordName"), record.get("ttl"), record.get("recordType"), recordValue);
		}
		
	}
	

	private static void printQuery(DNSResponse returnedData, byte buf1, byte buf2, String rootName, String fqdn) {
		System.out.print("\n\n");
		System.out.println("Query ID     " + returnedData.bytesToInt(buf1, buf2) + " " + fqdn + " --> " + rootName);
		System.out.println("Response ID: " + returnedData.getQueryId() + " " + "Authoritative " + returnedData.getAuthoritative());
		
		System.out.println("  Answers " + "(" + returnedData.getAnswerCount() + ")");
		printRecords(returnedData.getAnswerRecords());
		
		System.out.println("  Nameservers " + "(" + returnedData.getNsCount() + ")");
		printRecords(returnedData.getAuthoritativeRecords());
		
		System.out.println("  Additional Information " + "(" + returnedData.getAdditionalCount() + ")");
		printRecords(returnedData.getAdditionalRecords());
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

		
		// the query section starts at byte 12 of the packet data.
		int counter = 12;
		// set the QNAME
		String[] domainParts = fqdn.split("\\.");
		for (int i = 0; i<domainParts.length; i++) {
			byte[] domainBytes = domainParts[i].getBytes("UTF-8");
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

