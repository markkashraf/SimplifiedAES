#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>


#define uint16_t unsigned short int
#define uint8_t unsigned char


uint8_t const s_box[]={0x09, 0x04, 0x0a, 0x0b, 0x0d, 0x01, 0x08, 0x05, 0x06, 0x02, 0x00, 0x03, 0x0c, 0x0e, 0x0f, 0x07};
uint8_t const i_box[]={0x0a, 0x05, 0x09, 0x0b, 0x01, 0x07, 0x08, 0x0f, 0x06, 0x00, 0x02, 0x03, 0x0c, 0x04, 0x0d, 0x0e};
uint8_t const rcon[]={0x80,0x00,0x30};
uint8_t const mix[2][2]={{1,4},{4,1}};
uint8_t const imix[2][2]={{9,2},{2,9}};
uint16_t key=0x4af5;
uint16_t ciphertext,plaintext,decoded_ciphertext,skey[3]={0, 0, 0};
uint8_t round_key[6]={0, 0, 0, 0, 0, 0};

//substitute nibbles 16-bit, splits the input into 4 nibbles and-
//and gets the corresponding nibble from the s_box


uint8_t substitute_nibble(uint8_t sub){
    uint8_t temp1,temp2;
    temp1=(sub & 0xf0)>>4;
    temp2=(sub & 0x0f);
    return (s_box[temp1] << 4 | s_box[temp2]);
}

uint8_t shift_rows_8bit(uint8_t rot){
    return ((rot & 0xf0)>>4 | (rot & 0x0f)<<4);
}

uint16_t substitute_nibble_8bit(uint16_t c, uint8_t const box[]){
    uint16_t t1,t2,t3,t4;
    t1=(0xf000 & c)>>12;
    t2=(0x0f00 & c)>>8;
    t3=(0x00f0 & c)>>4;
    t4=(0x000f & c);
    return ((box[t1]<<12) | (box[t2]<<8) | (box[t3]<<4) | (box[t4]));
}
// shift rows of nibble
// can be simply done by exchanging the locations of the last 2nd, 4th nibbles
//shift_rows(DF1A) = DA1F
uint16_t shift_rows(uint16_t c){
    return ((c & 0x0f00)>>8 | (c & 0x000f)<<8 | (c & 0xf0f0));
}
//XOR a 16-bit round key into a 16-bit state.
uint16_t add_round_key(uint16_t m, uint16_t k){
    return (m^k);
}




void expand_key(){
    round_key[0]=(0xff00 & key) >> 8;
    round_key[1]=(0x00ff & key);
    int i;
    for(i=2;i<5;i=i+2){
        round_key[i]= round_key[i - 2] ^ rcon[i - 2] ^ substitute_nibble(shift_rows_8bit(round_key[i - 1]));
        round_key[i + 1]= round_key[i] ^ round_key[i - 1];
    }
}

//generating round keys
void get_round_key(){
    skey[0]=(round_key[0] << 8 | round_key[1]);
    skey[1]=(round_key[2] << 8 | round_key[3]);
    skey[2]=(round_key[4] << 8 | round_key[5]);
}



void round0(){
    ciphertext= add_round_key(plaintext, skey[0]);
}

void dround0(){
    decoded_ciphertext= add_round_key(ciphertext, skey[2]);
}
//polynomial multiplication
unsigned int short op(unsigned int short m1, unsigned int short m2){
    uint16_t res=0x0;
    uint16_t j=0;
    while(m1){
        res=((m1&0x0001)*(m2<<j))^res;
        m1=m1>>1;
        j=j+1;
    }
    return res;
}
//bitwise polynomial modulo 19 multiplication
uint16_t GF_2_4_multiply(uint16_t b1, uint16_t b2){
    uint16_t mul= op(b1, b2);

    uint16_t shift=0;
    while(mul > 15){
        shift=ceil(log(mul+1)/log(2))-ceil(log(0x13)/log(2));
        mul=mul^(0x13<<shift);
    }
    return mul;
}
//apply the matrix M on the 16 bit state (in GF(2^4))
uint16_t mix_columns(uint16_t c, unsigned const char m[][2]){
    uint16_t s[4],st[4];
    s[0]=((0xf000 & c)>>12)&0x000f;
    s[1]=(0x0f00 & c)>>8;
    s[2]=(0x00f0 & c)>>4;
    s[3]=(0x000f & c);

    st[0]= GF_2_4_multiply(m[0][0], s[0]) ^ GF_2_4_multiply(m[0][1], s[1]);

    st[1]= GF_2_4_multiply(m[0][1], s[0]) ^ GF_2_4_multiply(m[0][0], s[1]);

    st[2]= GF_2_4_multiply(m[1][1], s[2]) ^ GF_2_4_multiply(m[1][0], s[3]);

    st[3]= GF_2_4_multiply(m[1][0], s[2]) ^ GF_2_4_multiply(m[1][1], s[3]);

    return ((st[0]<<12) | (st[1]<<8) | (st[2]<<4) | (st[3]));
}
//round1
void round1(){
    ciphertext= substitute_nibble_8bit(ciphertext, s_box);
    ciphertext= shift_rows(ciphertext);
    ciphertext= mix_columns(ciphertext, mix);
    ciphertext= add_round_key(ciphertext, skey[1]);
}

void dround1(){
    decoded_ciphertext= substitute_nibble_8bit(decoded_ciphertext, i_box);

    decoded_ciphertext= shift_rows(decoded_ciphertext);

    decoded_ciphertext= add_round_key(decoded_ciphertext, skey[1]);

    decoded_ciphertext= mix_columns(decoded_ciphertext, imix);


}
//final round
void round2(){
    ciphertext= substitute_nibble_8bit(ciphertext, s_box);

    ciphertext= shift_rows(ciphertext);

    ciphertext= add_round_key(ciphertext, skey[2]);

}

void dround2(){
    decoded_ciphertext= substitute_nibble_8bit(decoded_ciphertext, i_box);
    decoded_ciphertext= shift_rows(decoded_ciphertext);
    decoded_ciphertext= add_round_key(decoded_ciphertext, skey[0]);
}
void encode(){
    round0();
    round1();
    round2();
}
void decode(){
    dround0();
    dround1();
    dround2();
}


int main(int argc, char* argv[]){
    int mode = -1;
    if(argc==1) {

        printf("Please enter operation:\n1.ENCODE\n2.DECODE\n");
        scanf("%d",&mode);

        if(mode ==1)
        {
            printf("\nEnter key (in hexadecimal):> 0x");
            scanf("%x", &key);
            printf("Enter plaintext (in hexadecimal):> 0x");
            scanf("%x", &plaintext);
        }
        if (mode == 2)
        {
            printf("\nEnter key (in hexadecimal):> 0x");
            scanf("%x", &key);
            printf("Enter ciphertext (in hexadecimal):> 0x");
            scanf("%x", &ciphertext);

        }


    }
    else if(argc == 4)
    {

        key = (int)strtol(argv[2], NULL, 16);
        if(!strcmp(argv[1],"ENC")) {
            mode = 1;
            plaintext = (int)strtol(argv[3], NULL, 16);
        }
        else if(!strcmp(argv[1],"DEC")) {
            mode = 2;
            ciphertext = (int)strtol(argv[3], NULL, 16);
        }
        else
        {
            printf("Error: wrong parameter format, please use \"./saes_1900156 ENC KEY PLAINTEXT)\" or \"saes_1900156 DEC KEY CIPHERTEXT\" to use the command-line mode.");
        }

    }
    else
    {
        printf("Error: wrong parameter format, please use \"./saes_1900156 ENC KEY PLAINTEXT)\" or \"saes_1900156 DEC KEY CIPHERTEXT\" to use the command-line mode.");
        return 0;
    }


    if(mode == 1)
    {
        expand_key();
        get_round_key();
        encode();
        printf("\nciphertext: 0x%X\n", ciphertext);
    }
    else if (mode == 2)
    {
        expand_key();
        get_round_key();
        decode();
        printf("\nplaintext: 0x%X\n", decoded_ciphertext);

    }

    return 0;
}
