
import java.net.InetAddress;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.*;




// Lots of the action associated with handling a DNS query is processing 
// the response. Although not required you might find the following skeleton of
// a DNSreponse helpful. The class below has bunch of instance data that typically needs to be 
// parsed from the response. If you decide to use this class keep in mind that it is just a 
// suggestion and feel free to add or delete methods to better suit your implementation as 
// well as instance variables.



public class DNSResponse {
    private int queryID;                  // this is for the response it must match the one in the request 
    private int answerCount = 0;          // number of answers  
    private boolean decoded = false;      // Was this response successfully decoded
    private int nsCount = 0;              // number of nscount response records
    private int additionalCount = 0;      // number of additional (alternate) response records
    private boolean authoritative = false;// Is this an authoritative record
    private int questionCount = 0;
    private boolean isResponse = false;
    private boolean truncation = false;
    private int responseCode = 0;
    private ArrayList<Map> answerRecords = new ArrayList<Map>();
    private ArrayList<Map> additionalRecords = new ArrayList<Map>();
    private ArrayList<Map> authoritativeRecords = new ArrayList<Map>();

    // Note you will almost certainly need some additional instance variables.

    // When in trace mode you probably want to dump out all the relevant information in a response

	// void dumpResponse() {

	// }

    public ArrayList<Map> getAdditionalRecords() {
        return additionalRecords;
    }

    public ArrayList<Map> getAnswerRecords() {
        return answerRecords;
    }

    public ArrayList<Map> getAuthoritativeRecords() {
        return authoritativeRecords;
    }

    public int getQueryId() {
        return queryID;
    }

    public boolean getAuthoritative() {
        return this.authoritative;
    }

    public int getAnswerCount() {
        return answerCount;
    }

    public int getNsCount() {
        return nsCount;
    }

    public int getAdditionalCount() {
        return additionalCount;
    }

    public int getResponseCode() {
        return responseCode;
    }

    public boolean checkQueryId(byte a, byte b) {

        int first = (int) a;
        int sec = (int) b;

        int lookupQueryId =  ((a << 8) & 0xFFFF) | (b & 0xFF);

        if (lookupQueryId == this.queryID) {
            return true;

        }
        return false;
    }
    // The constructor: you may want to add additional parameters, but the two shown are 
    // probably the minimum that you need.

	public DNSResponse (byte[] data, int len) throws Exception {

	    this.extractResponseHeader(data);
        int offset = this.skipQuerySection(12, data);
        offset = this.extractRecords(offset, data, answerCount, answerRecords);
        offset = this.extractRecords(offset, data, nsCount, authoritativeRecords);
        offset = extractRecords(offset, data, additionalCount, additionalRecords);
    }


    // You will also want methods to extract the response records and record
    // the important values they are returning. Note that an IPV6 reponse record
    // is of type 28. It probably wouldn't hurt to have a response record class to hold
    // these records. 

    private void extractResponseHeader(byte[] data) {
    	    //                                         1  1  1  1  1  1
    //   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                      ID                       |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                    QDCOUNT                    |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                    ANCOUNT                    |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                    NSCOUNT                    |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                    ARCOUNT                    |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        this.queryID = bytesToInt(data[0], data[1]);

        // determine whether this is a response or query packet
        int qr = ((int) data[2] >> 7) & 1;
		isResponse = intToBool(qr);
        int aa = ((int) data[2] >> 2) & 1;
        authoritative = intToBool(aa);

        int tc  = (data[2] >> 1) & 1;
        truncation = intToBool(tc);
        // TODO: what if response is truncated
        responseCode = data[3] & 15;
      
        this.questionCount = bytesToInt(data[4], data[5]);
        
        answerCount = bytesToInt(data[6], data[7]);
       
       	nsCount = bytesToInt(data[8], data[9]);
        additionalCount = bytesToInt(data[10], data[11]);
    }


    private int skipQuerySection (int queryOffset, byte[] data) {
        int length;
        for (int i = 0; i < questionCount; i++) {
        	// iterate throuugh the domain name
            while (data[queryOffset] != 0) {
                length = (int) data[queryOffset];
                for (int k = 0; k < length; k++) {
                    queryOffset++;
                }
                queryOffset++;
            }
            // skip the query class (2 bytes) and query type (2 bytes)
            queryOffset = queryOffset + 4;

		}
        return queryOffset;
    }


private int extractRecords(int offset, byte[] data, int loopCount, ArrayList<Map> records) {
        
    //      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                                               |
    // /                                               /
    // /                      NAME                     /
    // |                                               |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                      TYPE                     |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                     CLASS                     |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                      TTL                      |
    // |                                               |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                   RDLENGTH                    |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    // /                     RDATA                     /
    // /                                               /
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        for (int i = 0; i < loopCount; i++) {

            offset++;
            String domainName = "";
            int fqdnPointer = offset;
            boolean hasBeenCompressed = false;

            while (data[fqdnPointer] != 0){
                int isCompressed = ((int) data[fqdnPointer] >> 6) & 3;
                int length = 0;

                if (isCompressed == 0) {
                    length = (int) data[fqdnPointer];

                    if (!hasBeenCompressed) {
                        offset++;
                    }
                }

                else if (isCompressed == 3) {
                    fqdnPointer = this.getFqdnPointer(fqdnPointer, data);
                    length = (int) data[fqdnPointer];
                    if (!hasBeenCompressed) {
                        hasBeenCompressed = true;
                        offset+=2;
                    }
                }
                for (int y = 0; y < length; y++) {
                    fqdnPointer++;
                    domainName = domainName + Character.toString((char) data[fqdnPointer]);
                    if (!hasBeenCompressed) {
                        offset++;
                    }
                }
                domainName += ".";
                fqdnPointer++;
            }
            domainName = domainName.substring(0, domainName.length() - 1);

            //extract type

            int answerType = bytesToInt(data[offset], data[offset + 1]);
            offset++;
            String type = this.intToType(answerType);
           
            // extract class
            offset++;
            int classType = bytesToInt(data[offset], data[offset+1]);
            offset++;
            String ansClass = intToClass(classType);
            
            // extract ttl
            offset++;
            long ttl = bytesToLong(data[offset], data[offset+1], data[offset+2], data[offset+3]);
            offset = offset + 3;
            offset++;
                
            
           int rdataLength = bytesToInt(data[offset], data[offset+1]);
           offset++;

            String ip = "";
            // extract IP 
            if (classType == 1 && (answerType == 1 || answerType == 28 )) {
                if (answerType == 28) {
                    ip = this.extractIPV6(offset, rdataLength, data);
                }
                else {
                    ip = this.extractIP(offset, rdataLength, data);
                }
                offset = offset + rdataLength;
            }

            if ((classType == 1 && answerType == 5) || classType == 1 && answerType == 2) {
                offset++;
                fqdnPointer = offset;
                hasBeenCompressed = false;
                while (data[fqdnPointer] != 0){
                    int isCompressed = ((int) data[fqdnPointer] >> 6) & 3;
                    int length = 0;

                    if (isCompressed == 0) {
                        length = (int) data[fqdnPointer];

                    }

                    else if (isCompressed == 3) {
                        fqdnPointer = this.getFqdnPointer(fqdnPointer, data);
                        length = (int) data[fqdnPointer];
                        if (!hasBeenCompressed) {
                            hasBeenCompressed = true;
                        }
                    }
                    for (int y = 0; y < length; y++) {
                        fqdnPointer++;
                        ip = ip + Character.toString((char) data[fqdnPointer]);
                    }
                    ip += ".";
                    fqdnPointer++;
                }
                offset = offset + rdataLength - 1;
                ip = ip.substring(0, ip.length() - 1);
            }

            Map<String, String> record = new HashMap<String, String>();
            record.put("recordName", domainName);
            record.put("ttl", Long.toString(ttl));
            record.put("recordType", type);
            record.put("recordValue", ip);
//            for (String key : record.keySet()) {
//                System.out.println("Key = " + key + " - " + record.get(key));
//            }
            records.add(record);
        }
        return offset;
    }






    private String intToType(int answerType) {
    	String type;
        switch(answerType) {
			case 1:
				type = "A";
				break;   
			case 2 :
				type = "NS";	     
			break; 
			case 3 :
				type = "3";
			break; 
			case 4 :
				type = "4";
			break; 
			case 5 :
				type = "CN";
			break; 
			case 6 :
				type = "6";
			break; 
			case 7:
				type = "7";
			break; 
			case 8 :
				type = "8";
			break; 
			case 9 :
				type = "9";
			break; 
			case 10 :
				type = "10";
			break; 
			case 11 :
				type = "11";
			break; 
			case 12 :
				type = "12";
			break; 
			case 13 :
				type = "13";
			break; 
			case 14 :
				type = "14";
			break; 
			case 15 :
				type = "15";
			break; 
			case 16 :
				type = "16";
			break;
            case 28 :
                type = "AAAA";
                break;
            default :
				type = "ERROR: Not a valid type.";
			}

		return type;
    }

    private String intToClass(int classType) {
    	String ansClass;
        switch(classType) {
			case 1:
				ansClass = "IN";
				break;   
			case 2 :
				ansClass = "CS";	     
			break; 
			case 3 :
				ansClass = "CH";	     
			break; 
			case 4 :
				ansClass = "HS";	     
			break; 
			default :
				ansClass = "ERROR: invalid class type";	     
		}

		return ansClass;
    }


    private int getFqdnPointer(int offset, byte[] data) {
        return ((((int) data[offset]) & 63) << 6) | ((int) data[offset + 1] & 0xFF);
     //   return ((((int) data[offset]) & 63) << 8) | ((int) data[offset + 1] & 0xFF);
    }

    private String extractFqdn(int fqdnPointer, byte[] data) {
    	   String fqdn = "";
    	   int length = 0;
            while (data[fqdnPointer] != 0) {
                length = (int) data[fqdnPointer];
                for (int k = 0; k < length; k++) {

                    fqdnPointer++;
                    fqdn = fqdn + Character.toString((char) data[fqdnPointer]);
                }
                fqdn += ".";
                fqdnPointer++;

            }
            return fqdn.substring(0, fqdn.length() - 1);
    }

    private String extractIP(int offset, int length, byte[] data){
    	String ip = "";
        for (int j = 0; j < length; j++) {
            offset++;
            int ipDigit = (int) data[offset] & 0xff;
            String ipBit = Integer.toString(ipDigit);
            ip = ip + ipBit + ".";
            
        }
        return ip.substring(0, ip.length() - 1);
    }

    private String extractIPV6(int offset, int length, byte[] data){
        String ip = "";
        int j = 0;

        while (j < length) {
            offset++;
            String ipDigit1 = String.format("%02x", data[offset]);
            offset++;
            String ipDigit2 = String.format("%02x", data[offset]);
            String temp = ipDigit1 + ipDigit2;
            temp = temp.replaceFirst("^0+(?!$)", "");
            ip = ip + temp;
            ip = ip + ":";
            j+=2;
            
        }
        return ip.substring(0, ip.length() - 1);
    }


    public static int bytesToInt(byte higherOrderByte, byte lowerOrderByte) {
    	return (((int) higherOrderByte << 8) & 0xFFFF) | ( (int) lowerOrderByte & 0xFF);
    }

      public static long bytesToLong(byte byte1, byte byte2, byte byte3, byte byte4) {
    	return (((long) byte1 << 24) & 0xFFFFFFFFL) | (((long) byte2 << 16) & 0xFFFFFFL) | (((long) byte3 << 8) & 0xFFFFL) | ((long) byte4 & 0xFFL);
    }

    public static boolean intToBool(int convert) {
    	if (convert == 1) {
        	return true;
        }
        return false;
    }
}


