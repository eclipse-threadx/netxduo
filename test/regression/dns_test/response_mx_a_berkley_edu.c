/*
No.     Time        Source                Destination           Protocol Length Info
    108 142.849657  192.2.2.1             192.2.2.240           DNS      107    Standard query response 0x0002  MX 10 mx.berkeley.edu

Frame 108: 107 bytes on wire (856 bits), 107 bytes captured (856 bits)
Ethernet II, Src: TyanComp_45:7a:c6 (00:e0:81:45:7a:c6), Dst: Dell_8e:ec:b5 (d4:be:d9:8e:ec:b5)
Internet Protocol Version 4, Src: 192.2.2.1 (192.2.2.1), Dst: 192.2.2.240 (192.2.2.240)
User Datagram Protocol, Src Port: domain (53), Dst Port: 50825 (50825)
Domain Name System (response)
    [Request In: 107]
    [Time: 0.000166000 seconds]
    Transaction ID: 0x0002
    Flags: 0x8180 Standard query response, No error
    Questions: 1
    Answer RRs: 1
    Authority RRs: 0
    Additional RRs: 1
    Queries
    Answers
        berkeley.edu: type MX, class IN, preference 10, mx mx.berkeley.edu
            Name: berkeley.edu
            Type: MX (Mail exchange)
            Class: IN (0x0001)
            Time to live: 59 minutes, 53 seconds
            Data length: 7
            Preference: 10
            Mail exchange: mx.berkeley.edu
    Additional records
        mx.berkeley.edu: type A, class IN, addr 169.229.218.141
            Name: mx.berkeley.edu
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 59 minutes, 57 seconds
            Data length: 4
            Addr: 169.229.218.141 (169.229.218.141)

*/

/* Frame (107 bytes) */
char response_mx_a_berkley_edu_pkt[107] = {
0xd4, 0xbe, 0xd9, 0x8e, 0xec, 0xb5, 0x00, 0xe0, /* ........ */
0x81, 0x45, 0x7a, 0xc6, 0x08, 0x00, 0x45, 0x00, /* .Ez...E. */
0x00, 0x5d, 0x4d, 0x47, 0x00, 0x00, 0x80, 0x11, /* .]MG.... */
0x68, 0x53, 0xc0, 0x02, 0x02, 0x01, 0xc0, 0x02, /* hS...... */
0x02, 0xf0, 0x00, 0x35, 0xc6, 0x89, 0x00, 0x49, /* ...5...I */
0x90, 0x53, 0x00, 0x02, 0x81, 0x80, 0x00, 0x01, /* .S...... */
0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x62, /* .......b */
0x65, 0x72, 0x6b, 0x65, 0x6c, 0x65, 0x79, 0x03, /* erkeley. */
0x65, 0x64, 0x75, 0x00, 0x00, 0x0f, 0x00, 0x01, /* edu..... */
0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, /* ........ */
0x0e, 0x09, 0x00, 0x07, 0x00, 0x0a, 0x02, 0x6d, /* .......m */
0x78, 0xc0, 0x0c, 0xc0, 0x2c, 0x00, 0x01, 0x00, /* x...,... */
0x01, 0x00, 0x00, 0x0e, 0x0d, 0x00, 0x04, 0xa9, /* ........ */
0xe5, 0xda, 0x8d                                /* ... */
};

int response_mx_a_berkley_edu_pkt_size = 107;