#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>


//############################################MACROS###########################################
#define uint32_t unsigned int
#define uint16_t unsigned short int
#define uint8_t unsigned char
#define TEST_KEY 0x4AF5

// shift rows of nibble
// can be simply done by exchanging the locations of the last 2nd, 4th nibbles
//shift_rows(DF1A) = DA1F
#define shift_rows(r) ((r & 0x0f00) >> 8 | (r & 0x000f) << 8 | (r & 0xf0f0))
// can be simply done by exchanging the locations of the last 1st, 2nd nibbles
#define  shift_rows_8bit(r) ((r & 0xf0) >> 4 | (r & 0x0f) << 4)
//XOR a 16-bit round key into a 16-bit state.
#define add_round_key(x, y) (x^y)


//############################################CONSTANTS#########################################
uint8_t const SBOX[]={0x09, 0x04, 0x0a, 0x0b,
                      0x0d, 0x01, 0x08, 0x05,
                      0x06, 0x02, 0x00, 0x03,
                      0x0c, 0x0e, 0x0f, 0x07
};
uint8_t const INVERSE_SBOX[]={0x0a, 0x05, 0x09, 0x0b,
                              0x01, 0x07, 0x08, 0x0f,
                              0x06, 0x00, 0x02, 0x03,
                              0x0c, 0x04, 0x0d, 0x0e
};

uint8_t const RCON[]={0x80, 0x00, 0x30};
uint8_t const MIX_COLUMNS[2][2]={{1, 4}, {4, 1}};
uint8_t const INVERSE_MIX_COLUMNS[2][2]={{9, 2}, {2, 9}};



//############################################VARIABLES#########################################
uint16_t key = TEST_KEY;
uint16_t ciphertext, plaintext, decoded_ciphertext, round_key[3]={0, 0, 0};
uint8_t  round_key_gen[6]={0, 0, 0, 0, 0, 0};




//############################################ Substitution #########################################
// used for key expansion
uint8_t substitute_nibble_8bit(uint8_t sub){
    uint8_t x1,x2;
    x1=(sub & 0xf0) >> 4;
    x2=(sub & 0x0f);
    return (SBOX[x1] << 4 | SBOX[x2]);
}

//substitute nibbles 16-bit, splits the input into 4 nibbles and-
//and gets the corresponding nibble from the SBOX
uint16_t substitute_nibble_16bit(uint16_t x, uint8_t const s_box[]){
    uint16_t x1,x2,x3,x4;
    x1=(0xf000 & x) >> 12;
    x2=(0x0f00 & x) >> 8;
    x3=(0x00f0 & x) >> 4;
    x4=(0x000f & x);
    return ((s_box[x1] << 12) | (s_box[x2] << 8) | (s_box[x3] << 4) | (s_box[x4]));
}



//############################################ Key Generation #########################################
void expand_key(){
    round_key_gen[0]=(0xff00 & key) >> 8;
    round_key_gen[1]=(0x00ff & key);
    int i;
    for(i=2;i<5;i=i+2){
        round_key_gen[i]= round_key_gen[i - 2] ^ RCON[i - 2] ^ substitute_nibble_8bit(shift_rows_8bit(round_key_gen[i - 1]));
        round_key_gen[i + 1]= round_key_gen[i] ^ round_key_gen[i - 1];
    }
}

//generating round keys
void get_round_key(){
    round_key[0]=(round_key_gen[0] << 8 | round_key_gen[1]);
    round_key[1]=(round_key_gen[2] << 8 | round_key_gen[3]);
    round_key[2]=(round_key_gen[4] << 8 | round_key_gen[5]);
}



//########################################################## MIX COLUMNS ####################################################

//polynomial multiplication in GF(2^4)
uint16_t GF_2_4_multiply(uint16_t x1, uint16_t x2){
    uint16_t res=0;
    uint16_t i=0;
    while(x1){
        res= ((x1 & 0x0001) * (x2 << i)) ^ res;
        x1=x1 >> 1;
        i= i + 1;
    }

    uint32_t shift;
    while(res > 15){
        shift = (int)(ceil( log(res + 1) / log(2)) - ceil( log(0x13) / log(2)));
        res = res ^ (0x13 << shift);
    }
    return res;
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


void encode(){
    //Adding round key
    ciphertext = add_round_key(plaintext, round_key[0]);
    //Round 1
    ciphertext = substitute_nibble_16bit(ciphertext, SBOX);
    ciphertext = shift_rows(ciphertext);
    ciphertext = mix_columns(ciphertext, MIX_COLUMNS);
    ciphertext = add_round_key(ciphertext, round_key[1]);
    //Round 2
    ciphertext= substitute_nibble_16bit(ciphertext, SBOX);
    ciphertext= shift_rows(ciphertext);
    ciphertext= add_round_key(ciphertext, round_key[2]);
}
void decode(){
    //Adding round key
    decoded_ciphertext= add_round_key(ciphertext, round_key[2]);
    //Round 1
    decoded_ciphertext = substitute_nibble_16bit(decoded_ciphertext, INVERSE_SBOX);
    decoded_ciphertext = shift_rows(decoded_ciphertext);
    decoded_ciphertext = add_round_key(decoded_ciphertext, round_key[1]);
    decoded_ciphertext = mix_columns(decoded_ciphertext, INVERSE_MIX_COLUMNS);
    //Round 2
    decoded_ciphertext = substitute_nibble_16bit(decoded_ciphertext, INVERSE_SBOX);
    decoded_ciphertext = shift_rows(decoded_ciphertext);
    decoded_ciphertext = add_round_key(decoded_ciphertext, round_key[0]);
}


int main(int argc, char* argv[]){
    int mode = -1;
    if(argc==1) {

        printf("Please enter operation:\n1.ENCODE\n2.DECODE\n");
        scanf("%d",&mode);

        if(mode == 1)
        {
            printf("\nEnter key (in hexadecimal):> 0x");
            scanf("%hx", &key);
            printf("Enter plaintext (in hexadecimal):> 0x");
            scanf("%hx", &plaintext);
        }
        if (mode == 2)
        {
            printf("\nEnter key (in hexadecimal):> 0x");
            scanf("%hx", &key);
            printf("Enter ciphertext (in hexadecimal):> 0x");
            scanf("%hx", &ciphertext);

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
            printf("Error: wrong parameter format, please use \"./saes_1900156 ENC KEY PLAINTEXT\" or \"saes_1900156 DEC KEY CIPHERTEXT\" to use the command-line mode.");
        }

    }
    else
    {
        printf("Error: Wrong number of parameters, please use \"./saes_1900156 ENC KEY PLAINTEXT\" or \"saes_1900156 DEC KEY CIPHERTEXT\" to use the command-line mode.");
        return 0;
    }


    if(mode == 1)
    {
        expand_key();
        get_round_key();
        encode();
        printf("\n0x%X\n", ciphertext);
    }
    else if (mode == 2)
    {
        expand_key();
        get_round_key();
        decode();
        printf("\n0x%X\n", decoded_ciphertext);

    }

    return 0;
}
