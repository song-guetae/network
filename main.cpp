#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("%u bytes captured\n", header->caplen);
    if (packet[13] == 0){
    printf("-------------------------------TCP------------------------------------\n");
    printf("Protocol Type : 0x%02X%02x\n",packet[12], packet[13]);
    printf("Source Mac : %x:%x:%x:%x:%x:%x\n",packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
    printf("Destination Mac : %x:%x:%x:%x:%x:%x\n",packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);
    printf("Source IP : %d.%d.%d.%d\n",packet[26],packet[27],packet[28],packet[29]); 
    printf("Destination IP : %d.%d.%d.%d\n",packet[30],packet[31],packet[32],packet[33]);
    int src_port = (packet[34] << 8) + packet[35];
    int des_port = (packet[36]<<8) + packet[37];
    printf("Source Port : %d\n",src_port);
    printf("Destination Port : %d\n",des_port);
    int total_len = (packet[16] << 8) + packet[17];
    int ip_len = int(packet[14] & 0x0f);
    int tcp = (packet[13+ip_len*4+13] >> 4) & 0x0f;
    int tcp_len = tcp * 4;
    printf("total length : %d\n",total_len);
    printf("ip header length : %d\n",ip_len*4);
    printf("tcp header length : %d\n",tcp_len);
    int i;
    int data_len = total_len - ip_len*4 -tcp_len*4;
    for(i=total_len-data_len; i<data_len;i++){
    	printf("%02x",packet[i]);
    }
    printf("\n");
    printf("----------------------------------------------------------------------\n");}
  }	
  pcap_close(handle);
  return 0;
}
