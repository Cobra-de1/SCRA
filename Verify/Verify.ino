#include <stdlib.h>
#include <stdio.h>
#include <gmp-ino.h>
#include <time.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <ESP8266WiFi.h>
#include <WiFiUDP.h>
#include <SHA3.h>

#define MODULUS_SIZE 3072                       /* This is the number of bits we want in the modulus */
#define BLOCK_SIZE (MODULUS_SIZE / 8)           /* This is the size of a block that gets en/decrypted at once */
#define BUFFER_SIZE ((MODULUS_SIZE / 8) / 2)    /* This is the number of bytes in n and p */
#define HASH_SIZE 32                            /* This is size of choosen hash function, hash_size = hash_function_length // 8 */
#define HASH_BLOCK_NUM 32                       /* This is size of l */
#define HASH_BLOCK_LEN 256                      /* This is size of b, hash_block_len = 2 ^ b */
#define CONCAT_LEN (HASH_SIZE + 2)              /* This is length of (i||Mi||P) */
#define SIG_LEN (BLOCK_SIZE + 16)
#define MAX_PACKET_SIZE (10000 + SIG_LEN)

typedef struct {
    mpz_t n;                /* Modulus */
    mpz_t e;                /* Public Exponent */
    unsigned char pad[HASH_SIZE];    /* Padding */
} public_key;

WiFiUDP UDP;
boolean wifiConnected = false;
boolean udpConnected = false;
const char* ssid = "Thanh Dung";
const char* password = "0909112659";
int port = 8888;
IPAddress ip(192,168,100,200);
IPAddress gateway(192,168,100,1);  
IPAddress subnet(255,255,255,255); 

public_key kp;
unsigned char sig[BLOCK_SIZE];
unsigned char hashed[HASH_SIZE];
unsigned char packetBuffer[MAX_PACKET_SIZE];

void setup() {
  Serial.begin(115200);
  
   wifiConnected = connectWifi();  
  // only proceed if wifi connection successful
  if(wifiConnected){
    udpConnected = connectUDP();
    if (udpConnected){
      // initialise pins
      pinMode(5,OUTPUT);
    }
  }
  set_public_key();
}

void loop() {
  int packetSize = UDP.parsePacket();
  if(packetSize) {
    if (packetSize > MAX_PACKET_SIZE || packetSize < SIG_LEN) {
      Serial.println("Packet size not valid");
    } else {
      UDP.read(packetBuffer, MAX_PACKET_SIZE);
      int len = packetSize - (SIG_LEN);
      for (int i = 0; i < len; i++) {
        Serial.print((char)packetBuffer[i]);      
      }
      Serial.println("");
      SHA3_256 sha3;
      sha3.update(packetBuffer, (size_t)(len + 16));
      sha3.finalize(hashed, HASH_SIZE);
      Serial.print("Hashed: ");
      for (int i = 0; i < HASH_SIZE; i++) {
        if (hashed[i] < 16) {
          Serial.print(0);
        }
        Serial.print(hashed[i], HEX);      
      }
      Serial.println("");      
      for (int i = 0; i < BLOCK_SIZE; i++) {
        sig[i] = packetBuffer[i + len + 16];
      }
      Serial.print("Signature: ");
      for (int i = 0; i < BLOCK_SIZE; i++) {
        if (sig[i] < 16) {
          Serial.print(0);
        }
        Serial.print(sig[i], HEX);      
      }
      Serial.println("");
      int flag = 1;
      Serial.print("Time verify: ");
      Serial.println(verify(hashed, sig, &kp, &flag));
      if (!flag) {
        Serial.println("Verify Success");
      } else {
        Serial.println("Verify Failed");
      }
    }
  }

}

double verify(unsigned char* msg, unsigned char* sig, public_key* kp, int* status) {
    int start = millis();
    mpz_t mul;
    mpz_init(mul);
    mpz_import(mul, (BLOCK_SIZE), 1, sizeof(sig[0]), 0, 0, sig);
    mpz_powm(mul, mul, kp->e, kp->n);

    mpz_t tmp;
    mpz_init(tmp);
    mpz_set_ui(tmp, 1);

    mpz_t tmp2;
    mpz_init(tmp2);

    for (int i = 0; i < HASH_BLOCK_NUM; i++) {
        unsigned char mij[CONCAT_LEN];
        unsigned char hashed[HASH_SIZE];
        mij[0] = i;
        mij[1] = msg[i];
        for (int j = 0; j < HASH_SIZE; j++) {
            mij[j + 2] = kp->pad[j];
        }
        SHA3_256 sha3;
        sha3.update(mij, (size_t)(CONCAT_LEN));
        sha3.finalize(hashed, HASH_SIZE);
        mpz_import(tmp2, HASH_SIZE, 1, sizeof(hashed[0]), 0, 0, hashed);
        mpz_mul(tmp, tmp, tmp2);
        mpz_mod(tmp, tmp, kp->n);
    }
    *status = mpz_cmp(mul, tmp);    
    mpz_clear(mul);
    mpz_clear(tmp);
    mpz_clear(tmp2);
    int end = millis();
    return (double)(end - start) / CLOCKS_PER_SEC * 1000;
}

boolean connectWifi() {
  boolean state = true;
  int i = 0;
  WiFi.begin(ssid, password);
  Serial.println("");
  Serial.println("Connecting to WiFi");
  
  // Wait for connection
  Serial.print("Connecting");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
    if (i > 10){
      state = false;
      break;
    }
    i++;
  }
  if (state){
    Serial.println("");
    Serial.print("Connected to ");
    Serial.println(ssid);
    Serial.print("IP address: ");
    WiFi.config(ip,gateway,subnet);
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("");
    Serial.println("Connection failed.");
  }
  return state;
}

boolean connectUDP(){
  boolean state = false;
  
  Serial.println("");
  Serial.println("Connecting to UDP");
  
  if(UDP.begin(port) == 1){
    Serial.println("Connection successful");
    state = true;
  } else{
    Serial.println("Connection failed");
  }
  
  return state;
}

void set_public_key() {
  mpz_init(kp.n);
  mpz_init(kp.e);
  unsigned char tmp[BLOCK_SIZE] = {
    217, 211, 134, 93, 164, 38, 148, 183, 183, 88, 214, 152, 245, 37, 32, 167, 136, 254, 95, 29, 125, 247, 79, 
    47, 255, 236, 57, 117, 4, 22, 149, 84, 88, 31, 195, 116, 83, 140, 244, 210, 57, 182, 61, 230, 161, 217, 33, 
    29, 188, 120, 252, 247, 178, 3, 182, 64, 253, 215, 84, 7, 215, 41, 208, 18, 60, 224, 142, 32, 113, 196, 163, 
    1, 161, 204, 29, 134, 133, 51, 157, 53, 112, 118, 141, 123, 104, 201, 58, 41, 178, 0, 196, 200, 200, 138,   
    129, 175, 30, 9, 64, 129, 252, 197, 52, 142, 223, 194, 52, 222, 63, 95, 106, 31, 43, 222, 22, 238, 237, 246, 
    139, 102, 61, 235, 170, 139, 91, 240, 136, 17, 2, 126, 64, 101, 214, 230, 51, 107, 249, 242, 233, 10, 93, 40, 
    213, 26, 153, 58, 120, 222, 25, 159, 118, 238, 153, 127, 107, 176, 108, 32, 84, 90, 58, 149, 105, 201, 127, 123, 
    172, 64, 226, 226, 25, 66, 83, 211, 94, 210, 45, 23, 251, 229, 48, 19, 209, 56, 3, 67, 20, 139, 15, 48, 35, 204, 
    253, 3, 24, 59, 94, 188, 250, 40, 123, 80, 242, 89, 36, 12, 238, 37, 34, 168, 127, 99, 121, 156, 146, 42, 57, 
    233, 186, 188, 87, 159, 102, 112, 73, 182, 9, 107, 246, 4, 122, 124, 109, 217, 153, 49, 134, 118, 30, 112, 172, 
    205, 135, 86, 212, 160, 10, 57, 149, 115, 18, 177, 217, 49, 95, 37, 98, 245, 129, 153, 65, 223, 59, 42, 192, 
    113, 89, 135, 179, 134, 230, 133, 184, 3, 242, 164, 160, 1, 143, 109, 13, 7, 117, 135, 21, 119, 155, 192, 90, 
    146, 184, 241, 244, 110, 228, 183, 149, 29, 78, 217, 10, 235, 215, 245, 106, 108, 246, 62, 234, 91, 141, 252, 
    165, 170, 58, 224, 180, 122, 6, 45, 136, 44, 19, 113, 119, 9, 113, 26, 113, 115, 113, 33, 188, 253, 142, 150, 
    12, 59, 108, 64, 163, 23, 164, 91, 189, 74, 0, 211, 202, 114, 166, 246, 82, 55, 11, 82, 162, 196, 103, 206, 
    197, 207, 178, 171, 148, 104, 150, 139, 254, 149, 234, 74, 171, 52, 221, 123, 2, 42, 157, 124, 167, 195, 175, 75 };
  mpz_import(kp.n, (BLOCK_SIZE), 1, sizeof(tmp[0]), 0, 0, tmp);
  mpz_set_ui(kp.e, 65537);
  kp.pad[0] = 9;
  kp.pad[1] = 51;
  kp.pad[2] = 147;
  kp.pad[3] = 197;
  kp.pad[4] = 42;
  kp.pad[5] = 109;
  kp.pad[6] = 100;
  kp.pad[7] = 63;
  kp.pad[8] = 161;
  kp.pad[9] = 215;
  kp.pad[10] = 62;
  kp.pad[11] = 64;
  kp.pad[12] = 116;
  kp.pad[13] = 220;
  kp.pad[14] = 181;
  kp.pad[15] = 55;
  kp.pad[16] = 8;
  kp.pad[17] = 119;
  kp.pad[18] = 158;
  kp.pad[19] = 56;
  kp.pad[20] = 189;
  kp.pad[21] = 244;
  kp.pad[22] = 245;
  kp.pad[23] = 192;
  kp.pad[24] = 110;
  kp.pad[25] = 145;
  kp.pad[26] = 246;
  kp.pad[27] = 156;
  kp.pad[28] = 146;
  kp.pad[29] = 12;
  kp.pad[30] = 167;
  kp.pad[31] = 183;
}
