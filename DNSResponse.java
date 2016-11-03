
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

	void dumpResponse() {

        //System.out.println("hello client");

	}

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

    boolean checkQueryId(byte a, byte b) {

        int first = (int) a;
        int sec = (int) b;

        int lookupQueryId =  ((a << 8) & 0xFFFF) | (b & 0xFF);

        if (lookupQueryId == this.queryID) {
            //System.out.println("true!!");
            return true;

        }
        return false;
    }
    // The constructor: you may want to add additional parameters, but the two shown are 
    // probably the minimum that you need.

	public DNSResponse (byte[] data, int len) throws Exception {

	    this.extractResponseHeader(data);
        int offset = this.skipQuerySection(12, data);
        offset = this.extractAnswerSection(offset, data);
        offset = this.extractAuthoritativeSection(offset, data);
        offset = this.extractAdditionalSection(offset, data);
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
		// System.out.println(isResponse);
		if(!isResponse) {
			// TODO: error handling
			System.out.println("ERROR");
		}

        int aa = ((int) data[2] >> 2) & 1;
        authoritative = intToBool(aa);

        int tc  = (data[2] >> 1) & 1;
        truncation = intToBool(tc);
        // TODO: what if response is truncated
        //System.out.println(truncated);
        responseCode = data[3] & 15;
      
        this.questionCount = bytesToInt(data[4], data[5]);
        System.out.println("questionCount :" + questionCount);
        
        answerCount = bytesToInt(data[6], data[7]);
        System.out.println("answerCount :" + answerCount);
       
       	nsCount = bytesToInt(data[8], data[9]);
        additionalCount = bytesToInt(data[8], data[9]);
        System.out.println("additionalCount: " + additionalCount);

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


    private int extractAnswerSection(int offset, byte[] data) {
    	
    // 	    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
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
        System.out.println("Asnwer section starts");
        for (int i = 0; i < answerCount; i++) {

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
            System.out.println("Name: " + domainName);

            //extract type

           	int answerType = bytesToInt(data[offset], data[offset + 1]);
    		offset++;
            String type = this.intToType(answerType);
            System.out.println("Type: " + type);
           
            // extract class
            offset++;
            int classType = bytesToInt(data[offset], data[offset+1]);
            offset++;
            String ansClass = intToClass(classType);
            System.out.println("class: " + ansClass);
            
            // extract ttl
            offset++;
            long ttl = bytesToLong(data[offset], data[offset+1], data[offset+2], data[offset+3]);
            offset = offset + 3;
            System.out.println("Time to live: " + ttl);
            offset++;
    	        
    		
           int rdataLength = bytesToInt(data[offset], data[offset+1]);
           offset++;

            // System.out.println("Data Length: " + rdataLength);

            String ip = "";
            // extract IP 
            if (classType == 1 && answerType == 1) {
                ip = this.extractIP(offset, rdataLength, data);
                System.out.println("Address: " + ip);
                offset = offset + rdataLength;
            }

            Map<String, String> record = new HashMap<String, String>();
            record.put("recordName", domainName);
            record.put("ttl", Long.toString(ttl));
            record.put("recordType", type);
            record.put("recordValue", ip);
//            for (String key : record.keySet()) {
//                System.out.println("Key = " + key + " - " + record.get(key));
//            }
            answerRecords.add(record);
        }
    	return offset;
    }


    private int extractAuthoritativeSection(int offset, byte[] data) {

        // 	    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
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

        System.out.println("Authoritative section starts");
        //System.out.println("Offset at start " + offset);
        for (int i = 0; i < nsCount; i++) {
//            offset++;
//            // get fqdn pointer
//            int length;
//            int fqdnPointer = offset;
//            // check of the data is compressed
//            int isCompressed = ((int) data[offset] >> 6) & 3;
//            if (isCompressed == 0b00) {
//                length = (int) data[offset];
//            } else if (isCompressed == 3) {
//                fqdnPointer = this.getFqdnPointer(offset, data);
//            }
//
////            System.out.println("fp: " + fqdnPointer);
//            offset++;
//            // extract fqdn
//            String fqdn = this.extractFqdn(fqdnPointer, data);
//            System.out.println("Name: " + fqdn);

            offset++;
            String name = "";
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
                    name = name + Character.toString((char) data[fqdnPointer]);
                    if (!hasBeenCompressed) {
                        offset++;
                    }
                }
                name += ".";
                fqdnPointer++;
            }
            name = name.substring(0, name.length() - 1);
            System.out.println("Name: " + name);


            //extract type

            int answerType = bytesToInt(data[offset], data[offset + 1]);
            offset++;
            String type = this.intToType(answerType);
            System.out.println("Type: " + type);

            // extract class
            offset++;
            int classType = bytesToInt(data[offset], data[offset + 1]);
            offset++;
            String ansClass = intToClass(classType);
            System.out.println("class: " + ansClass);

            // extract ttl
            offset++;
            long ttl = bytesToLong(data[offset], data[offset + 1], data[offset + 2], data[offset + 3]);
            offset = offset + 3;
            System.out.println("Time to live: " + ttl);
            offset++;
            System.out.println("TTL offset: " + offset);


            int rdataLength = bytesToInt(data[offset], data[offset + 1]);
            offset +=2;


            System.out.println("Data Length: " + rdataLength);

            String domainName = "";
             //extract IP
            if (classType == 1 && answerType == 1) {
                String ip = this.extractIP(offset, rdataLength, data);
                System.out.println("Address: " + ip);
                offset = offset + rdataLength;
            }

          else if (classType == 1 && answerType == 2) {
                domainName = "";
                int len = 0;
                int w = 0;
                while ( w < rdataLength) {
                    int isACompressed = ((int) data[offset] >> 6) & 3;
                    if (isACompressed == 0) {
                        len = (int) data[offset];
                        for (int j = 0; j < len; j++) {
                            offset++;
                            w++;
                            domainName = domainName + Character.toString((char) data[offset]);
                        }
                        domainName += ".";
                    } else if (isACompressed == 3) {
                        w++;
                        fqdnPointer = this.getFqdnPointer(offset, data);
                        int klength = 0;
                        while (data[fqdnPointer] != 0) {
                            klength = (int) data[fqdnPointer];
                            for (int k = 0; k < klength; k++) {

                                fqdnPointer++;
                                domainName = domainName + Character.toString((char) data[fqdnPointer]);
                            }
                            domainName += ".";
                            fqdnPointer++;

                        }
                    }
                    offset++;
                    w++;
                }

              domainName = domainName.substring(0, domainName.length() - 1);
              System.out.println("Name Server: " + domainName);


            }
            Map<String, String> record = new HashMap<String, String>();
            record.put("recordName", name);
            record.put("ttl", Long.toString(ttl));
            record.put("recordType", type);
            record.put("recordValue", domainName);
//            for (String key : record.keySet()) {
//                System.out.println("Key = " + key + " - " + record.get(key));
//            }
            authoritativeRecords.add(record);
        }
        return offset;
    }


    private int extractAdditionalSection(int offset, byte[] data) {

        System.out.println("Additional");

        for (int i = 0; i < additionalCount; i++) {
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
            System.out.println("Name: " + domainName);

            //extract type

            int answerType = bytesToInt(data[offset], data[offset + 1]);
            offset++;
            String type = this.intToType(answerType);
            System.out.println("adType: " + type);

            // extract class
            offset++;
            int classType = bytesToInt(data[offset], data[offset + 1]);
            offset++;
            String ansClass = intToClass(classType);
            System.out.println("adclass: " + ansClass);

            // extract ttl
            offset++;
            long ttl = bytesToLong(data[offset], data[offset + 1], data[offset + 2], data[offset + 3]);
            offset = offset + 3;
            System.out.println("Time to live: " + ttl);
            offset++;

            int rdataLength = bytesToInt(data[offset], data[offset + 1]);
            offset ++;

            String ip = "";
            //extract IP
            if (classType == 1 && answerType == 1) {
                ip = this.extractIP(offset, rdataLength, data);
                System.out.println("adAddress: " + ip);
                offset = offset + rdataLength;
            }

            Map<String, String> record = new HashMap<String, String>();
            record.put("recordName", domainName);
            record.put("ttl", Long.toString(ttl));
            record.put("recordType", type);
            record.put("recordValue", ip);
//            for (String key : record.keySet()) {
//                System.out.println("Key = " + key + " - " + record.get(key));
//            }
            additionalRecords.add(record);

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
				type = "MD";	     
			break; 
			case 4 :
				type = "MF";	     
			break; 
			case 5 :
				type = "CNAME";	     
			break; 
			case 6 :
				type = "SOA";	     
			break; 
			case 7:
				type = "MB";	     
			break; 
			case 8 :
				type = "MG";	     
			break; 
			case 9 :
				type = "MR";	     
			break; 
			case 10 :
				type = "NULL";	     
			break; 
			case 11 :
				type = "WKS";	     
			break; 
			case 12 :
				type = "PTR";	     
			break; 
			case 13 :
				type = "HINFO";	     
			break; 
			case 14 :
				type = "MINFO";	     
			break; 
			case 15 :
				type = "MX";	     
			break; 
			case 16 :
				type = "TXT";	     
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
        System.out.println("IP offset "+ offset);
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


