/*
No.     Time        Source                Destination           Protocol Length Info
     50 57.439998   192.2.2.1             192.2.2.240           DNS      258    Standard query response 0x0003  MX 20 alt1.aspmx.l.google.com MX 30 alt2.aspmx.l.google.com MX 40 alt3.aspmx.l.google.com MX 50 alt4.aspmx.l.google.com MX 10 aspmx.l.google.com

Frame 50: 258 bytes on wire (2064 bits), 258 bytes captured (2064 bits)
Ethernet II, Src: TyanComp_45:7a:c6 (00:e0:81:45:7a:c6), Dst: Dell_8e:ec:b5 (d4:be:d9:8e:ec:b5)
Internet Protocol Version 4, Src: 192.2.2.1 (192.2.2.1), Dst: 192.2.2.240 (192.2.2.240)
User Datagram Protocol, Src Port: domain (53), Dst Port: 52423 (52423)
Domain Name System (response)
    [Request In: 49]
    [Time: 0.221586000 seconds]
    Transaction ID: 0x0003
    Flags: 0x8180 Standard query response, No error
    Questions: 1
    Answer RRs: 5
    Authority RRs: 0
    Additional RRs: 5
    Queries
    Answers
        google.com: type MX, class IN, preference 20, mx alt1.aspmx.l.google.com
            Name: google.com
            Type: MX (Mail exchange)
            Class: IN (0x0001)
            Time to live: 9 minutes, 59 seconds
            Data length: 17
            Preference: 20
            Mail exchange: alt1.aspmx.l.google.com
        google.com: type MX, class IN, preference 30, mx alt2.aspmx.l.google.com
            Name: google.com
            Type: MX (Mail exchange)
            Class: IN (0x0001)
            Time to live: 9 minutes, 59 seconds
            Data length: 9
            Preference: 30
            Mail exchange: alt2.aspmx.l.google.com
        google.com: type MX, class IN, preference 40, mx alt3.aspmx.l.google.com
            Name: google.com
            Type: MX (Mail exchange)
            Class: IN (0x0001)
            Time to live: 9 minutes, 59 seconds
            Data length: 9
            Preference: 40
            Mail exchange: alt3.aspmx.l.google.com
        google.com: type MX, class IN, preference 50, mx alt4.aspmx.l.google.com
            Name: google.com
            Type: MX (Mail exchange)
            Class: IN (0x0001)
            Time to live: 9 minutes, 59 seconds
            Data length: 9
            Preference: 50
            Mail exchange: alt4.aspmx.l.google.com
        google.com: type MX, class IN, preference 10, mx aspmx.l.google.com
            Name: google.com
            Type: MX (Mail exchange)
            Class: IN (0x0001)
            Time to live: 9 minutes, 59 seconds
            Data length: 4
            Preference: 10
            Mail exchange: aspmx.l.google.com
    Additional records
        alt1.aspmx.l.google.com: type A, class IN, addr 209.85.225.26
            Name: alt1.aspmx.l.google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 1 minute, 50 seconds
            Data length: 4
            Addr: 209.85.225.26 (209.85.225.26)
        alt2.aspmx.l.google.com: type A, class IN, addr 74.125.130.26
            Name: alt2.aspmx.l.google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 30 seconds
            Data length: 4
            Addr: 74.125.130.26 (74.125.130.26)
        alt3.aspmx.l.google.com: type A, class IN, addr 173.194.76.26
            Name: alt3.aspmx.l.google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 4 minutes, 53 seconds
            Data length: 4
            Addr: 173.194.76.26 (173.194.76.26)
        alt4.aspmx.l.google.com: type A, class IN, addr 173.194.73.26
            Name: alt4.aspmx.l.google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 4 minutes, 53 seconds
            Data length: 4
            Addr: 173.194.73.26 (173.194.73.26)
        aspmx.l.google.com: type A, class IN, addr 173.194.79.26
            Name: aspmx.l.google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 4 minutes, 52 seconds
            Data length: 4
            Addr: 173.194.79.26 (173.194.79.26)
*/

/* Frame (258 bytes) */
char response_mx_a_google_com_pkt[258] = {
0xd4, 0xbe, 0xd9, 0x8e, 0xec, 0xb5, 0x00, 0xe0, /* ........ */
0x81, 0x45, 0x7a, 0xc6, 0x08, 0x00, 0x45, 0x00, /* .Ez...E. */
0x00, 0xf4, 0x4a, 0x8d, 0x00, 0x00, 0x80, 0x11, /* ..J..... */
0x6a, 0x76, 0xc0, 0x02, 0x02, 0x01, 0xc0, 0x02, /* jv...... */
0x02, 0xf0, 0x00, 0x35, 0xcc, 0xc7, 0x00, 0xe0, /* ...5.... */
0x30, 0x39, 0x00, 0x03, 0x81, 0x80, 0x00, 0x01, /* 09...... */
0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x06, 0x67, /* .......g */
0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, /* oogle.co */
0x6d, 0x00, 0x00, 0x0f, 0x00, 0x01, 0xc0, 0x0c, /* m....... */
0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x02, 0x57, /* .......W */
0x00, 0x11, 0x00, 0x14, 0x04, 0x61, 0x6c, 0x74, /* .....alt */
0x31, 0x05, 0x61, 0x73, 0x70, 0x6d, 0x78, 0x01, /* 1.aspmx. */
0x6c, 0xc0, 0x0c, 0xc0, 0x0c, 0x00, 0x0f, 0x00, /* l....... */
0x01, 0x00, 0x00, 0x02, 0x57, 0x00, 0x09, 0x00, /* ....W... */
0x1e, 0x04, 0x61, 0x6c, 0x74, 0x32, 0xc0, 0x2f, /* ..alt2./ */
0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, /* ........ */
0x02, 0x57, 0x00, 0x09, 0x00, 0x28, 0x04, 0x61, /* .W...(.a */
0x6c, 0x74, 0x33, 0xc0, 0x2f, 0xc0, 0x0c, 0x00, /* lt3./... */
0x0f, 0x00, 0x01, 0x00, 0x00, 0x02, 0x57, 0x00, /* ......W. */
0x09, 0x00, 0x32, 0x04, 0x61, 0x6c, 0x74, 0x34, /* ..2.alt4 */
0xc0, 0x2f, 0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, /* ./...... */
0x00, 0x00, 0x02, 0x57, 0x00, 0x04, 0x00, 0x0a, /* ...W.... */
0xc0, 0x2f, 0xc0, 0x2a, 0x00, 0x01, 0x00, 0x01, /* ./.*.... */
0x00, 0x00, 0x00, 0x6e, 0x00, 0x04, 0xd1, 0x55, /* ...n...U */
0xe1, 0x1a, 0xc0, 0x47, 0x00, 0x01, 0x00, 0x01, /* ...G.... */
0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0x4a, 0x7d, /* ......J} */
0x82, 0x1a, 0xc0, 0x5c, 0x00, 0x01, 0x00, 0x01, /* ...\.... */
0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xad, 0xc2, /* ...%.... */
0x4c, 0x1a, 0xc0, 0x71, 0x00, 0x01, 0x00, 0x01, /* L..q.... */
0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xad, 0xc2, /* ...%.... */
0x49, 0x1a, 0xc0, 0x86, 0x00, 0x01, 0x00, 0x01, /* I....... */
0x00, 0x00, 0x01, 0x24, 0x00, 0x04, 0xad, 0xc2, /* ...$.... */
0x4f, 0x1a                                      /* O. */
};

int response_mx_a_google_com_pkt_size = 258;
