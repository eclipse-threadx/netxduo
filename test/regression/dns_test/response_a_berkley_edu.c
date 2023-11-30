/*
No.     Time        Source                Destination           Protocol Length Info
    130 168.629156  192.2.2.1             192.2.2.240           DNS      88     Standard query response 0x0002  A 169.229.216.200

Frame 130: 88 bytes on wire (704 bits), 88 bytes captured (704 bits)
Ethernet II, Src: TyanComp_45:7a:c6 (00:e0:81:45:7a:c6), Dst: Dell_8e:ec:b5 (d4:be:d9:8e:ec:b5)
Internet Protocol Version 4, Src: 192.2.2.1 (192.2.2.1), Dst: 192.2.2.240 (192.2.2.240)
User Datagram Protocol, Src Port: domain (53), Dst Port: 55271 (55271)
Domain Name System (response)
    [Request In: 129]
    [Time: 0.000138000 seconds]
    Transaction ID: 0x0002
    Flags: 0x8180 Standard query response, No error
    Questions: 1
    Answer RRs: 1
    Authority RRs: 0
    Additional RRs: 0
    Queries
    Answers
        berkeley.edu: type A, class IN, addr 169.229.216.200
            Name: berkeley.edu
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 4 minutes, 59 seconds
            Data length: 4
            Addr: 169.229.216.200 (169.229.216.200)
*/

/* Frame (88 bytes) */
char response_a_berkley_edu_pkt[88] = {
0xd4, 0xbe, 0xd9, 0x8e, 0xec, 0xb5, 0x00, 0xe0, /* ........ */
0x81, 0x45, 0x7a, 0xc6, 0x08, 0x00, 0x45, 0x00, /* .Ez...E. */
0x00, 0x4a, 0x4d, 0xc2, 0x00, 0x00, 0x80, 0x11, /* .JM..... */
0x67, 0xeb, 0xc0, 0x02, 0x02, 0x01, 0xc0, 0x02, /* g....... */
0x02, 0xf0, 0x00, 0x35, 0xd7, 0xe7, 0x00, 0x36, /* ...5...6 */
0x43, 0xf5, 0x00, 0x02, 0x81, 0x80, 0x00, 0x01, /* C....... */
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x62, /* .......b */
0x65, 0x72, 0x6b, 0x65, 0x6c, 0x65, 0x79, 0x03, /* erkeley. */
0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x00, 0x01, /* edu..... */
0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, /* ........ */
0x01, 0x2b, 0x00, 0x04, 0xa9, 0xe5, 0xd8, 0xc8  /* .+...... */
};

int response_a_berkley_edu_pkt_size = 88;
