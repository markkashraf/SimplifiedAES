#include <stdio.h>
#include "math.h"
#define uint16_t unsigned short int
#define uint8_t unsigned char

// S_box used in the substitute_nibbles() function
uint8_t s_box[] ={0x09,0x04,0x0a,0x0b,
                  0x0d,0x01,0x08,0x05,
                  0x06,0x02,0x00,0x03,
                  0x0c,0x0e,0x0f,0x07
};


uint8_t ibox[]={0x0a,0x05,0x09,0x0b,0x01,0x07,0x08,0x0f,0x06,0x00,0x02,0x03,0x0c,0x04,0x0d,0x0e};
uint8_t rcon[]={0x80,0x00,0x30};
uint8_t mix[2][2]={{1,4},{4,1}};
uint8_t imix[2][2]={{9,2},{2,9}};
uint16_t key=0x4af5;
uint16_t ciph,msg,dmsg,skey[3]={0,0,0};
uint8_t wkey[6]={0,0,0,0,0,0};





//XOR a 16-bit round key into a 16-bit state.

uint16_t add_round_key(uint16_t s,uint16_t w){
    return (s^w);
}



//substitute nibbles 16-bit, splits the input into 4 nibbles and-
//and gets the corresponding nibble from the s_box

uint16_t substitute_nibbles(uint16_t x, uint16_t s_box[]){
    uint16_t x1,x2,x3,x4;
    x1=(0xf000 & x) >> 12;
    x2=(0x0f00 & x) >> 8;
    x3=(0x00f0 & x) >> 4;
    x4=(0x000f & x);
    return ((s_box[x1]<<12) | (s_box[x2]<<8) | (s_box[x3]<<4) | (s_box[x4]));
}

// shift rows of nibble
// can be simply done by exchanging the locations of the last 2nd, 4th nibbles
//shift_rows(DF1A) = DA1F
uint16_t shift_rows(uint16_t x){
    uint16_t x1,x2,x3;
    x1 = (x & 0x0f00) >> 8; // 3rd nibble in 2nd   (xFxx -->> xxxF)
    x2 = (x & 0x000f) << 8; // 4th nibble in 3rd   (xxxA  -->> xAxx)
    x3 = (x & 0xf0f0);      // (Dx1x)
    return (x1 | x2 | x3);
}



uint16_t op(uint16_t x1, uint16_t x2){
    uint16_t res=0x0;
    uint16_t i=0;

    for(int i = 0; x1; i++)
    {
        res= ((x1 & 0x0001) * (x2 << i) ) ^ res;
        x1 = x1 >> 1;
    }
    return res;
}

uint16_t GF_2_4_multiply(uint16_t b1, uint16_t b2){
    uint16_t res = op(b1, b2);
    uint16_t shift = 0;

    while(!(res<=15)){
        shift=ceil(log(res+1)/log(2))-ceil(log(0x13)/log(2));
        res=res^(0x13<<shift);
    }
    return res;
}


//apply the matrix M on the 16 bit state (in GF(2^4))
uint16_t mix_columns(uint16_t x,uint8_t m[][2])
{
    uint16_t s[4], res[4];
    // convert the 16 bits input to 4 nibbles
    s[0]=((0xf000 & x)>>12) & 0x000f;
    s[1]=(0x0f00 & x)>>8;
    s[2]=(0x00f0 & x)>>4;
    s[3]=(0x000f & x);

    // matrix multiplications in GF(2^4)
    res[0]= GF_2_4_multiply(m[0][0], s[0]) ^ GF_2_4_multiply(m[0][1], s[1]);
    res[1]= GF_2_4_multiply(m[0][1], s[0]) ^ GF_2_4_multiply(m[0][0], s[1]);
    res[2]= GF_2_4_multiply(m[1][1], s[2]) ^ GF_2_4_multiply(m[1][0], s[3]);
    res[3]= GF_2_4_multiply(m[1][0], s[2]) ^ GF_2_4_multiply(m[1][1], s[3]);
    return ((res[0] << 12) | (res[1] << 8) | (res[2] << 4) | res[3]);
}








int main() {
    printf("Hello, World!\n");
    return 0;
}
