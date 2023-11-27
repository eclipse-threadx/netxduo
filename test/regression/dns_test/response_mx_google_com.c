/*
No.     Time        Source           Destination      Protocol   Length  Info
42    2.441991000      192.168.0.1        192.168.0.105       DNS        178         Standard query response 0x0002 MX 40 alt3.aspmx.l.google.com MX 30 alt2.aspmx.l.google.com MX 10 aspmx.l.google.com MX 20 alt1.aspmx.l.google.com MX 50 alt4.aspmx.l.google.com

Frame 171: 178 bytes on wire (1424 bits), 178 bytes captured (1424 bits)
Ethernet II, Src: TendaTec_60:4b:46 (c8:3a:35:60:4b:46), Dst: Dell_33:c1:bd (18:03:73:33:c1:bd)
Internet Protocol Version 4, Src: 192.168.0.1 (192.168.0.1), Dst: 192.168.0.105 (192.168.0.105)
User Datagram Protocol, Src Port: domain (53), Dst Port: 53738 (53738)
Domain Name System (response)
    Request In: 164
    Time: 0.037374000 seconds
    Transaction ID: 0x0002
    Flags: 0x8180 (Standard query response, No error)
       Questions: 1
       Answer RRs: 5
       Authority RRs: 0
       Additional RRs: 0
    Queries
       google.com: type MX, class IN
    Answers
       google.com: type MX, class IN, preference 50, mx alt4.aspmx.l.google.com
            Name: google.com
            Type: MX (Mail exchange)
            Class: IN (0x0001)
            Time to live: 10 minutes
            Data length: 17
            Preference: 50
            Mail exchange: alt4.aspmx.l.google.com
       google.com: type MX, class IN, preference 30, mx alt2.aspmx.l.google.com
            Name: google.com
            Type: MX (Mail exchange)
            Class: IN (0x0001)
            Time to live: 10 minutes
            Data length: 9
            Preference: 30
            Mail exchange: alt2.aspmx.l.google.com
       google.com: type MX, class IN, preference 10, mx aspmx.l.google.com
            Name: google.com
            Type: MX (Mail exchange)
            Class: IN (0x0001)
            Time to live: 10 minutes
            Data length: 4
            Preference: 10
            Mail exchange: aspmx.l.google.com
       google.com: type MX, class IN, preference 20, mx alt1.aspmx.l.google.com
            Name: google.com
            Type: MX (Mail exchange)
            Class: IN (0x0001)
            Time to live: 10 minutes
            Data length: 9
            Preference: 20
            Mail exchange: alt1.aspmx.l.google.com
       google.com: type MX, class IN, preference 40, mx alt3.aspmx.l.google.com
            Name: google.com
            Type: MX (Mail exchange)
            Class: IN (0x0001)
            Time to live: 10 minutes
            Data length: 9
            Preference: 40
            Mail exchange: alt3.aspmx.l.google.com
*/

char response_mx_google_com_pkt[178] = {
0x18, 0x03, 0x73, 0x33, 0xc1, 0xbd, 0xc8, 0x3a, 
0x35, 0x60, 0x4b, 0x46, 0x08, 0x00, 0x45, 0x00, 
0x00, 0xa4, 0x98, 0xa1, 0x00, 0x00, 0x40, 0x11, 
0x5f, 0xed, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 
0x00, 0x69, 0x00, 0x35, 0xd1, 0xea, 0x00, 0x90, 
0x68, 0x6a, 0x00, 0x02, 0x81, 0x80, 0x00, 0x01, 
0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 
0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 
0x6d, 0x00, 0x00, 0x0f, 0x00, 0x01, 0xc0, 0x0c, 
0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 
0x00, 0x11, 0x00, 0x32, 0x04, 0x61, 0x6c, 0x74, 
0x34, 0x05, 0x61, 0x73, 0x70, 0x6d, 0x78, 0x01, 
0x6c, 0xc0, 0x0c, 0xc0, 0x0c, 0x00, 0x0f, 0x00, 
0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x09, 0x00, 
0x1e, 0x04, 0x61, 0x6c, 0x74, 0x32, 0xc0, 0x2f, 
0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 
0x02, 0x58, 0x00, 0x04, 0x00, 0x0a, 0xc0, 0x2f, 
0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 
0x02, 0x58, 0x00, 0x09, 0x00, 0x14, 0x04, 0x61, 
0x6c, 0x74, 0x31, 0xc0, 0x2f, 0xc0, 0x0c, 0x00, 
0x0f, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 
0x09, 0x00, 0x28, 0x04, 0x61, 0x6c, 0x74, 0x33, 
0xc0, 0x2f 
};

int response_mx_google_com_pkt_size = sizeof(response_mx_google_com_pkt);