/*
No.     Time        Source                Destination           Protocol Length Info
     54 82.002033   192.2.2.1             192.2.2.240           DNS      246    Standard query response 0x0002  A 74.125.224.194 A 74.125.224.195 A 74.125.224.196 A 74.125.224.197 A 74.125.224.198 A 74.125.224.199 A 74.125.224.200 A 74.125.224.201 A 74.125.224.206 A 74.125.224.192 A 74.125.224.193

Frame 54: 246 bytes on wire (1968 bits), 246 bytes captured (1968 bits)
Ethernet II, Src: TyanComp_45:7a:c6 (00:e0:81:45:7a:c6), Dst: Dell_8e:ec:b5 (d4:be:d9:8e:ec:b5)
Internet Protocol Version 4, Src: 192.2.2.1 (192.2.2.1), Dst: 192.2.2.240 (192.2.2.240)
User Datagram Protocol, Src Port: domain (53), Dst Port: 52427 (52427)
Domain Name System (response)
    [Request In: 53]
    [Time: 0.015609000 seconds]
    Transaction ID: 0x0002
    Flags: 0x8180 Standard query response, No error
    Questions: 1
    Answer RRs: 11
    Authority RRs: 0
    Additional RRs: 0
    Queries
    Answers
        google.com: type A, class IN, addr 74.125.224.194
            Name: google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 2 minutes, 22 seconds
            Data length: 4
            Addr: 74.125.224.194 (74.125.224.194)
        google.com: type A, class IN, addr 74.125.224.195
            Name: google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 2 minutes, 22 seconds
            Data length: 4
            Addr: 74.125.224.195 (74.125.224.195)
        google.com: type A, class IN, addr 74.125.224.196
            Name: google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 2 minutes, 22 seconds
            Data length: 4
            Addr: 74.125.224.196 (74.125.224.196)
        google.com: type A, class IN, addr 74.125.224.197
            Name: google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 2 minutes, 22 seconds
            Data length: 4
            Addr: 74.125.224.197 (74.125.224.197)
        google.com: type A, class IN, addr 74.125.224.198
            Name: google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 2 minutes, 22 seconds
            Data length: 4
            Addr: 74.125.224.198 (74.125.224.198)
        google.com: type A, class IN, addr 74.125.224.199
            Name: google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 2 minutes, 22 seconds
            Data length: 4
            Addr: 74.125.224.199 (74.125.224.199)
        google.com: type A, class IN, addr 74.125.224.200
            Name: google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 2 minutes, 22 seconds
            Data length: 4
            Addr: 74.125.224.200 (74.125.224.200)
        google.com: type A, class IN, addr 74.125.224.201
            Name: google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 2 minutes, 22 seconds
            Data length: 4
            Addr: 74.125.224.201 (74.125.224.201)
        google.com: type A, class IN, addr 74.125.224.206
            Name: google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 2 minutes, 22 seconds
            Data length: 4
            Addr: 74.125.224.206 (74.125.224.206)
        google.com: type A, class IN, addr 74.125.224.192
            Name: google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 2 minutes, 22 seconds
            Data length: 4
            Addr: 74.125.224.192 (74.125.224.192)
        google.com: type A, class IN, addr 74.125.224.193
            Name: google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 2 minutes, 22 seconds
            Data length: 4
            Addr: 74.125.224.193 (74.125.224.193)
*/

/* Frame (246 bytes) */
char response_a_google_com_pkt[246] = {
0xd4, 0xbe, 0xd9, 0x8e, 0xec, 0xb5, 0x00, 0xe0, /* ........ */
0x81, 0x45, 0x7a, 0xc6, 0x08, 0x00, 0x45, 0x00, /* .Ez...E. */
0x00, 0xe8, 0x4b, 0x83, 0x00, 0x00, 0x80, 0x11, /* ..K..... */
0x69, 0x8c, 0xc0, 0x02, 0x02, 0x01, 0xc0, 0x02, /* i....... */
0x02, 0xf0, 0x00, 0x35, 0xcc, 0xcb, 0x00, 0xd4, /* ...5.... */
0xf5, 0x39, 0x00, 0x02, 0x81, 0x80, 0x00, 0x01, /* .9...... */
0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, /* .......g */
0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, /* oogle.co */
0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, /* m....... */
0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8e, /* ........ */
0x00, 0x04, 0x4a, 0x7d, 0xe0, 0xc2, 0xc0, 0x0c, /* ..J}.... */
0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8e, /* ........ */
0x00, 0x04, 0x4a, 0x7d, 0xe0, 0xc3, 0xc0, 0x0c, /* ..J}.... */
0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8e, /* ........ */
0x00, 0x04, 0x4a, 0x7d, 0xe0, 0xc4, 0xc0, 0x0c, /* ..J}.... */
0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8e, /* ........ */
0x00, 0x04, 0x4a, 0x7d, 0xe0, 0xc5, 0xc0, 0x0c, /* ..J}.... */
0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8e, /* ........ */
0x00, 0x04, 0x4a, 0x7d, 0xe0, 0xc6, 0xc0, 0x0c, /* ..J}.... */
0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8e, /* ........ */
0x00, 0x04, 0x4a, 0x7d, 0xe0, 0xc7, 0xc0, 0x0c, /* ..J}.... */
0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8e, /* ........ */
0x00, 0x04, 0x4a, 0x7d, 0xe0, 0xc8, 0xc0, 0x0c, /* ..J}.... */
0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8e, /* ........ */
0x00, 0x04, 0x4a, 0x7d, 0xe0, 0xc9, 0xc0, 0x0c, /* ..J}.... */
0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8e, /* ........ */
0x00, 0x04, 0x4a, 0x7d, 0xe0, 0xce, 0xc0, 0x0c, /* ..J}.... */
0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8e, /* ........ */
0x00, 0x04, 0x4a, 0x7d, 0xe0, 0xc0, 0xc0, 0x0c, /* ..J}.... */
0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8e, /* ........ */
0x00, 0x04, 0x4a, 0x7d, 0xe0, 0xc1              /* ..J}.. */
};

int response_a_google_com_pkt_size = 246;
