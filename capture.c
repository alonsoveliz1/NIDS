#include <stdio.h> 
#include <pcap.h>
#include <string.h>

void list_devices();

int main(int argc, char *argv[]){
  
  
  char *alldevs = NULL;  
  char errbuff[PCAP_ERRBUF_SIZE];

  if(argc == 2){
    if(strcmp(argv[1], "list") == 0){
      list_devices();
      return 0;
    } // Si no digo que me liste los dispositivos y lo que hacen es darme un dispositivo de la lista -> capturo
  } 
  else{
      printf("As no device was selected, setting up default capturing interface \n");
      
      pcap_if_t *alldevs;
      int result = pcap_findalldevs(&alldevs, errbuff);
      
      // Si devuelve -1 no ha podido encontrar interfaces
      if(result == PCAP_ERROR){
        fprintf(stderr, "Error finding the device interfaces \n", errbuff); // Cambiar por stderr
        return -1;
      } else{
        if(alldevs == NULL){ // Si el primer elemento de la linked list es NULL no hay interfaces disponibles
          fprintf(stderr, "The device has no interfaces available \n", errbuff);
          return -1;
      } else{
        pcap_if_t *dev;
        dev = strdup(alldevs->name);
        printf("No device specified, switching to default device %s", dev);
        pcap_freealldevs(alldevs);
        printf("If you want to capture from another specify it like ./capture /"device/" ");
        return 0;
      }
    } 
  }

  return 0;
}



void list_devices(){
  pcap_if_t *alldevs, *d;
  char errbuff[PCAP_ERRBUF_SIZE];
  
  if(pcap_findalldevs(&alldevs, errbuff) == -1){
    fprintf(stderr, "Error trying to get the network devices: %s", errbuff);
  }
  else if(alldevs == NULL){
    printf("There are no devices available for packet capture \n");
  }
  else{
    while(alldevs->next != NULL){
      printf("Device: %s \n" , alldevs->name);
      alldevs = alldevs->next;
    }
  }
}
