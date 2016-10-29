
import java.net.InetAddress;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;




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

    // Note you will almost certainly need some additional instance variables.

    // When in trace mode you probably want to dump out all the relevant information in a response

	void dumpResponse() {

        //System.out.println("hello client");

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

	    
	    // The following are probably some of the things 
	    // you will need to do.
	    // Extract the query ID

	    // Make sure the message is a query response and determine
	    // if it is an authoritative response or note

	    // determine answer count

	    // determine NS Count

	    // determine additional record count

	    // Extract list of answers, name server, and additional information response 
	    // records
        int first = (int) data[0];
        int sec = (int) data[1];
        queryID = ((first << 8) & 0xFFFF) | (sec & 0xFF);
        //System.out.println(queryID);

        int answer = (int) data[2];
        answer = (answer >> 7) & 1;
        //System.out.println(answer);
        if (answer != 1) {
            //System.out.println("ERROR");
        }

        int auth = data[2];
        auth = (auth >> 2) & 1;
        //System.out.println(auth);

        if (auth == 0) {
            authoritative = true;
        }
        else {
            authoritative = false;
        }

        //bool

        int truncated = data[2];
        truncated = (truncated >> 1) & 1;
        //System.out.println(truncated);

        int responseCode = data[3];
        responseCode = responseCode & 15;
        //System.out.println(responseCode);

        int fpart = (int) data[4];
        int spart = (int) data[5];
        int questionCount = ((fpart << 8) & 0xFFFF) | (spart & 0xFF);
        //System.out.println(questionCount);

        int one = (int) data[6];
        int two = (int) data[7];
        int answerCount = ((one << 8) & 0xFFFF) | (two & 0xFF);
        //System.out.println(answerCount);

        int o = (int) data[8];
        int t = (int) data[9];
        int nsCount = ((o << 8) & 0xFFFF) | (t & 0xFF);
       // System.out.println(nsCount);

        int a = (int) data[10];
        int b = (int) data[11];
        int additionalCount = ((a << 8) & 0xFFFF) | (b & 0xFF);
        //System.out.println(additionalCount);

        int counter = 12;
        String domainName = "";
        int length;
        for (int i = 0; i <questionCount; i++) {
            while (data[counter] != 0) {
                length = (int) data[counter];

                for (int k = 0; k < length; k++) {

                    counter++;
                   char part =  (char) data[counter];
                    String dom = Character.toString(part);
                    domainName = domainName + dom;
                }
                domainName += ".";
                counter++;

            }

            domainName = domainName.substring(0, domainName.length()-1);
            //System.out.println(domainName);

            counter++;
            int t1 = (int) data[counter];
            counter++;
            int t2 = (int) data[counter];
            int type = ((t1 << 8) & 0xFFFF) | (t2 & 0xFF);
            if (type == 1) {
                //System.out.println("Type: A (Host Address)");
            }

            counter++;
            int c1 = (int) data[counter];
            counter++;
            int c2 = (int) data[counter];
            int classType = ((c1 << 8) & 0xFFFF) | (c2 & 0xFF);
            if (classType == 1) {
                //System.out.println("Class: IN");
            }
            else if (classType == 2) {
                //System.out.println("Class: CS");
            }
            else if (classType == 3) {
                //System.out.println("Class: CH");
            }
            else if (classType == 4) {
               // System.out.println("Class: HS");
            }


        }
        for (int yaml = 0; yaml < answerCount; yaml++) {
            counter++;

            int compressionPointer = (int) data[counter];
            compressionPointer = (compressionPointer >> 6) & 3;
            if (compressionPointer == 0b00) {
                int lengths = (int) data[counter];
            }

            int compression = 0;
            if (compressionPointer == 3) {
                int compressionFirst = (((int) data[counter]) & 63) << 6;
                counter++;
                int compressionSecond = (int) data[counter] & 0xFF;
                compression = compressionFirst | compressionSecond;

            }
            System.out.println("compress" + compression);

            String dName = "";
            while (data[compression] != 0) {
                length = (int) data[compression];

                for (int k = 0; k < length; k++) {

                    compression++;
                    char part = (char) data[compression];
                    String dom = Character.toString(part);
                    dName = dName + dom;
                }
                dName += ".";
                compression++;

            }

            dName = dName.substring(0, dName.length() - 1);
            System.out.println(dName);

            counter++;
            int t1 = (int) data[counter];
            counter++;
            int t2 = (int) data[counter];
            int type = ((t1 << 8) & 0xFFFF) | (t2 & 0xFF);
            if (type == 1) {
                System.out.println("Type: A (Host Address)");
            }

            counter++;
            int c1 = (int) data[counter];
            counter++;
            int c2 = (int) data[counter];
            int classType = ((c1 << 8) & 0xFFFF) | (c2 & 0xFF);
            if (classType == 1) {
                System.out.println("Class: IN");
            } else if (classType == 2) {
                //System.out.println("Class: CS");
            } else if (classType == 3) {
                //System.out.println("Class: CH");
            } else if (classType == 4) {
                // System.out.println("Class: HS");
            }


            int jj = counter + 1;
            //System.out.println(jj);
            for (int i = 0; i < 4; i++) {
                int r = jj + i;
                //            System.out.println(r);
                //            System.out.println(String.format("%x", data[r]) + " " );
            }

            counter++;
            //System.out.println(counter);
            int ttl1 = (int) data[counter];
            counter++;
            int ttl2 = (int) data[counter];

            counter++;
            int ttl3 = (int) data[counter];
            counter++;
            int ttl4 = (int) data[counter];

            //System.out.println(String.format("%x", ((ttl1 << 24) & 0xFFFFFFFFL) | ((ttl2 << 16) & 0xFFFFFFL) | ((ttl3 << 8) & 0xFFFFL) | (ttl4 & 0xFFL)) + " " );

            long ttl = ((ttl1 << 24) & 0xFFFFFFFFL) | ((ttl2 << 16) & 0xFFFFFFL) | ((ttl3 << 8) & 0xFFFFL) | (ttl4 & 0xFFL);
            System.out.println("Time to live: " + ttl);

            counter++;
            int rdl1 = (int) data[counter];
            counter++;
            int rdl2 = (int) data[counter];

            int rdataLength = ((rdl1 << 8) & 0xFFFF) | (rdl2 & 0xFF);

            System.out.println("Data Length: " + rdataLength);

            if (classType == 1 && type == 1) {
                String ip = "";
                for (int i = 0; i < rdataLength; i++) {
                    counter++;
                    int ipDigit = (int) data[counter] & 0xff;
                    String ipBit = Integer.toString(ipDigit);
                    ip = ip + ipBit + ".";
                }
                ip = ip.substring(0, ip.length() - 1);
                System.out.println("Address: " + ip);


            }
        }


    }



    // You will probably want a methods to extract a compressed FQDN, IP address
    // cname, authoritative DNS servers and other values like the query ID etc.


    // You will also want methods to extract the response records and record
    // the important values they are returning. Note that an IPV6 reponse record
    // is of type 28. It probably wouldn't hurt to have a response record class to hold
    // these records. 
}


