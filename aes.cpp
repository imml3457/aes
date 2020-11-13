/***
 * AES of 128, 192, 256 bit keys by Ian Mulet
 * The main functions were taken by the FIPS 197 documentation
 * The global vectors were given and can be found online 
 * I apologize for the excessive use of prints for debugging
 * I should've made a function for it, but it works
***/
#include <cstring>
#include <iostream>
#include <stdio.h>
#include <array>
#include <vector>
#include <sstream>

using namespace std;

//given vectors
vector<unsigned char> sbox = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
  };

vector<unsigned char> inv_sbox= {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d, };

//simple ffAdd from FIPS
unsigned char ffAdd(unsigned char x, unsigned char y){
    return x ^ y;
}

unsigned char xtime(unsigned char x){
    //and x with a high bit mask to check b_7
    if(x & 0x80){ //if not reduced
        //this was taken from the FIPS documentation
        x <<= 1;
        x ^= 0x1b;
        x &= 0xff;  //and with a mask to get the bits we want
    }
    else{ //if reduced
        x <<= 1;
    }
    return x;
}

unsigned char ffMultiply(unsigned char x, unsigned char y){
    unsigned char p = 0;
    //simply iterating and using a bit shift to multiply the two bytes
    for(int i = 0; i < 8; i++){
        if (y & 1){
            //using add if y & 1 != 0
            p = ffAdd(p, x);
        }
        //keep track of the xtime function
        //and shift y
        x = xtime(x);
        y >>= 1;
    }
    return p;
}

void subWord(vector<unsigned char> &a){
    //simply substitute every bit of the byte from sbox
    for(int i = 0; i < 4; i++){
        a[i] = sbox[a[i]];
    }
}

void rotWord(vector<unsigned char> &a){
    //move the first index to the last
    int temp = a[0];
    a.erase(a.begin());
    a.push_back(temp);
    
}

void xorBytes(vector<unsigned char> &x, vector<unsigned char> y){
    //helper function for key expansion
    //xor's a pair of bytes
    for(int i = 0; i < 4; i++){
        x[i] = x[i] ^ y[i];
    }
}

void Rcon(vector<unsigned char> &a, int n){
    //getting rcon based on index instead of having a given vector
    //this makes it easier in my opinion in keyexpansion
    //my method had the byte split up in a vector i.e [0x00, 0x10, 0x20...]
    //this returns it formatted like this
    unsigned char c = 1;
    for (int i = 0; i < n - 1; i++){
        c = xtime(c);   //get xtime
    }
    a[0] = c;   //xtime is the first 
    a[1] = a[2] = a[3] = 0; //zeros for the rest so 0x01000000 is a return
}

void keyExpansion(vector<unsigned char> key, vector<unsigned char> &word, int nk, int nb, int nr){
    //this method is taken from FIPS
    //there is pseudocode for this function
    vector<unsigned char> temp;
    vector<unsigned char> temprcon;
    //padding for formatted vector
    int padding = 4;
    temp.resize(4);
    temprcon.resize(4);
    int i = 0;
    //resize vector
    while(i < padding * nk){
        word[i] = key[i];
        i++;
    }
    i = padding * nk;
    while (i < padding * nb * (nr + 1)){
        for(int j = 0; j < 4; j++){
            temp[j] = word[i - padding + j];
        }
        //assign temp based upon the byte in word
        if(i / padding % nk == 0){
            rotWord(temp);
            subWord(temp);
            Rcon(temprcon, i / (nk * padding));
            xorBytes(temp, temprcon);
            //taken from FIPS
        }
        else if (nk > 6 && i / padding % nk == 4){
            //if the AES method is 256 bit
            subWord(temp);
        }
        for(int j = 0; j < 4; j++){
            //adding the expanded key to word
            word[i + j] = word[i + j - (padding * nk)] ^ temp[j];
        }
        i += 4;
    }
    temp.clear();
    temprcon.clear();
}

void subBytes(vector<vector<unsigned char>> &state, int nb){
    //simply substituting the states bits from sbox
    unsigned char temp;
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < nb; j++){
            temp = state[i][j];
            state[i][j] = sbox[temp];
        }
    }
}

void shiftRow(vector<vector<unsigned char>> &state, int x, int y, int nb){
    //shifting a single row of the state
    vector<unsigned char> temp;
    temp.resize(nb);
    for(int i = 0; i < nb; i++){
        //find the row that you want to shift using y coordinate
        temp[i] = state[x][(i + y) % nb];
    }
    //shift it based on given x coordinate
    state[x] = temp;
}

void shiftRows(vector<vector<unsigned char>> &state, int nb){
    //shifting each row
    for(int i = 1; i < 4; i++){
        shiftRow(state, i, i, nb);
    }
}

void mixColumn(vector<unsigned char> &col){
    //this is taken straight from FIPS the formula is in section 5
    vector<unsigned char> temp;
    temp = col;
    col[0] = ffMultiply(0x02, temp[0]) ^ ffMultiply(0x03, temp[1]) ^ temp[2] ^ temp[3];
    col[1] = (temp[0] ^ ffMultiply(0x02, temp[1])) ^ (ffMultiply(0x03, temp[2]) ^ temp[3]);
    col[2] = temp[0] ^ temp[1] ^ (ffMultiply(0x02, temp[2]) ^ ffMultiply(0x03, temp[3]));
    col[3] = (ffMultiply(0x03, temp[0]) ^ temp[1]) ^ temp[2] ^ ffMultiply(0x02, temp[3]);
}

void mixColumns(vector<vector<unsigned char>> &state){
    //simply shifting all the rows in state
    vector<unsigned char> temp;
    temp.resize(4);
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            //get the row
            temp[j] = state[j][i];    
        }
        //shifting
        mixColumn(temp);
        //putting it back into state
        for(int j = 0; j < 4; j++){
            state[j][i] = temp[j];
        }
    }
    temp.clear();
}

void addRoundKey(vector<vector<unsigned char>> &state, vector<unsigned char> w, int round, int nb, bool flag, int nr){
    //cal is used to find where to start in the expanded key
    int cal = (round * 4) * nb;
    int temp = nr - round;
    if(flag == 1){
        cout << "round[" << temp << "].ik_sch ";
    }
    else{
        cout << "round[" << round << "].k_sch ";
    }
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            printf("%02x", w[cal]);
            //xor the state with expanded key
            state[j][i] = state[j][i] ^ w[cal];
            cal++;
        }
    }
    cout << endl;
}

void cipher(vector<unsigned char> in, vector<unsigned char> &out, vector<unsigned char> word, int nk, int nb, int nr){
    //algorithm was taken straight from FIPS section 5.1
    vector<vector<unsigned char>> state;
    //resizing state
    state.resize(4);
    int z = 0;
    for(int i = 0; i < 4; i++){
        state[i].resize(4);
    }
    //taking in the plaintext and converting it into state
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            state[j][i] = in[z];
            z++;
        }
    }
    cout << "round[0].input ";
    for(int i = 0; i < state.size(); i++){
        for(int j = 0; j < state[0].size(); j++){
            printf("%02x", state[j][i]);
        }
    }
    cout << endl;
    /***below is running what is stated in FIPS
    addroundkey
    for loop of rounds
    sub
    shift
    mix
    add
    end for loop
    sub
    shift
    add in that order ***/
    addRoundKey(state, word, 0, nb, 0, nr);

    for(int i = 1; i < nr; i++){

    cout << "round[" << i << "].start ";
    for(int i = 0; i < state.size(); i++){
        for(int j = 0; j < state[0].size(); j++){
            printf("%02x", state[j][i]);
        }
    }
    cout << endl;

        subBytes(state, nb);

    cout << "round[" << i << "].s_box ";
    for(int i = 0; i < state.size(); i++){
        for(int j = 0; j < state[0].size(); j++){
            printf("%02x", state[j][i]);
        }
    }
    cout << endl;

        shiftRows(state, nb);

    cout << "round[" << i << "].s_row ";
    for(int i = 0; i < state.size(); i++){
        for(int j = 0; j < state[0].size(); j++){
            printf("%02x", state[j][i]);
        }
    }
    cout << endl;

        mixColumns(state);

    cout << "round[" << i << "].m_col ";
    for(int i = 0; i < state.size(); i++){
        for(int j = 0; j < state[0].size(); j++){
            printf("%02x", state[j][i]);
        }
    }
    cout << endl;

        addRoundKey(state, word, i, nb, 0, nr);
    }

    cout << "round[" << nr << "].start ";
    for(int i = 0; i < state.size(); i++){
        for(int j = 0; j < state[0].size(); j++){
            printf("%02x", state[j][i]);
        }
    }
    cout << endl;

    subBytes(state, nb);

    cout << "round[" << nr << "].s_box ";
    for(int i = 0; i < state.size(); i++){
        for(int j = 0; j < state[0].size(); j++){
            printf("%02x", state[j][i]);
        }
    }
    cout << endl;

    shiftRows(state, nb);

    cout << "round[" << nr << "].s_row ";
    for(int i = 0; i < state.size(); i++){
        for(int j = 0; j < state[0].size(); j++){
            printf("%02x", state[j][i]);
        }
    }
    cout << endl;

    addRoundKey(state, word, nr, nb, 0, nr);
    z = 0;
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            out[z] = state[j][i];
            z++;
        }
    }    
}

void invsubBytes(vector<vector<unsigned char>> &state, int nb){
    //same as subBytes but using inv_sbox
    unsigned char temp;
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < nb; j++){
            state[i][j] = inv_sbox[state[i][j]];
        }
    }
}


void invshiftRows(vector<vector<unsigned char>> &state, int nb){
    //same as shiftrows but starting in reverse
    for(int i = 1; i < 4; i++){
        shiftRow(state, i, nb - i, nb);
    }
}

void invmixColumn(vector<unsigned char> &col){
    //taken straight from FIPS 5.3.3
    vector<unsigned char> temp;
    temp = col;
    col[0] = ffMultiply(0x0e, temp[0]) ^ ffMultiply(0x0b, temp[1]) ^ ffMultiply(0x0d, temp[2]) ^ ffMultiply(0x09, temp[3]);
    col[1] = ffMultiply(0x09, temp[0]) ^ ffMultiply(0x0e, temp[1]) ^ ffMultiply(0x0b, temp[2]) ^ ffMultiply(0x0d, temp[3]);
    col[2] = ffMultiply(0x0d, temp[0]) ^ ffMultiply(0x09, temp[1]) ^ ffMultiply(0x0e, temp[2]) ^ ffMultiply(0x0b, temp[3]);
    col[3] = ffMultiply(0x0b, temp[0]) ^ ffMultiply(0x0d, temp[1]) ^ ffMultiply(0x09, temp[2]) ^ ffMultiply(0x0e, temp[3]);
}

void invmixColumns(vector<vector<unsigned char>> &state){
    vector<unsigned char> temp;
    temp.resize(4);
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            //get the col
            temp[j] = state[j][i];    
        }
        //invmix the col
        invmixColumn(temp);
        for(int j = 0; j < 4; j++){
            //emplace the col
            state[j][i] = temp[j];
        }
    }
    temp.clear();
}

void invcipher(vector<unsigned char> in, vector<unsigned char> &out, vector<unsigned char> word, int nk, int nb, int nr){
    /***
     * same as cipher taken from pseudocode in the FIPS doc
     * add
     * for loop counting down rounds
     * invshift
     * invsub
     * add
     * invmix
     * end foor loop
     * invshift
     * invsub
     * add in that order ***/

    vector<vector<unsigned char>> state;
    state.resize(4);
    int z = 0;
    for(int i = 0; i < 4; i++){
        state[i].resize(4);
    }

    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            state[j][i] = in[z];
            z++;
        }
    }

    cout << "round[0].iinput ";
    for(int i = 0; i < state.size(); i++){
        for(int j = 0; j < state[0].size(); j++){
            printf("%02x", state[j][i]);
        }
    }
    cout << endl;
    
    addRoundKey(state, word, nr, nb, 1, nr);

    for(int i = nr-1; i >= 1; i--){

        cout << "round[" << nr - i  << "].istart ";
        for(int i = 0; i < state.size(); i++){
            for(int j = 0; j < state[0].size(); j++){
                printf("%02x", state[j][i]);
            }
        }
        cout << endl;


        invshiftRows(state, nb);

        cout << "round[" << nr - i  << "].is_row ";
        for(int i = 0; i < state.size(); i++){
            for(int j = 0; j < state[0].size(); j++){
                printf("%02x", state[j][i]);
            }
        }
        cout << endl;


        invsubBytes(state, nb);

        cout << "round[" << nr - i  << "].is_box ";
        for(int i = 0; i < state.size(); i++){
            for(int j = 0; j < state[0].size(); j++){
                printf("%02x", state[j][i]);
            }
        }
        cout << endl;

        addRoundKey(state, word, i, nb, 1, nr);

        cout << "round[" << nr - i  << "].ik_add ";
        for(int i = 0; i < state.size(); i++){
            for(int j = 0; j < state[0].size(); j++){
                printf("%02x", state[j][i]);
            }
        }
        cout << endl;
        invmixColumns(state);
    }

    cout << "round[" << nr << "].istart ";
    for(int i = 0; i < state.size(); i++){
        for(int j = 0; j < state[0].size(); j++){
            printf("%02x", state[j][i]);
        }
    }
    cout << endl;

    invshiftRows(state, nb);

    cout << "round[" << nr << "].is_row ";
    for(int i = 0; i < state.size(); i++){
        for(int j = 0; j < state[0].size(); j++){
            printf("%02x", state[j][i]);
        }
    }
    cout << endl;

    invsubBytes(state, nb);

    cout << "round[" << nr << "].is_box ";
    for(int i = 0; i < state.size(); i++){
        for(int j = 0; j < state[0].size(); j++){
            printf("%02x", state[j][i]);
        }
    }
    cout << endl;    

    addRoundKey(state, word, 0, nb, 1, nr);
    z = 0;
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            out[z] = state[j][i];
            z++;
        }
    }    
}

int main(){

//plain text for memory
string plaintext = "00112233445566778899aabbccddeeff";


//keys for 128, 192, 256 tests
vector<unsigned char> key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
vector<unsigned char> key1 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
vector<unsigned char> key2 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
vector<unsigned char> word;
vector<unsigned char> word1;
vector<unsigned char> word2;
//plain text in formatted vector
vector<unsigned char> in = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
vector<unsigned char> out;
vector<unsigned char> out2;
out.resize(4*4);
out2.resize(4*4);
word.resize(176);
word1.resize(52*4);
word2.resize(60*4);
int nb = 4;
int nk = 4;
int nr = 10;
//testing AES 128
keyExpansion(key, word, nk, nb, nr);
cout << "AES 128" << endl;
cout << "Cipher (encrypt)" << endl;
cipher(in, out, word, nk, nb, nr);
cout << "round[" << nr << "].output ";
for(int i = 0; i < out.size(); i++){
    printf("%02x", out[i]);
}
cout << endl;
cout << endl;
cout << "invCipher (decrypt)" << endl;
invcipher(out, out2, word, nk, nb, nr);
cout << "round[" << nr << "].ioutput ";
for(int i = 0; i < out2.size(); i++){
    printf("%02x", out2[i]);
}
cout << endl << endl;



nk = 6;
nr = 12;
//testing AES 192
keyExpansion(key1, word1, nk, nb, nr);
cout << "AES 192" << endl;
cout << "Cipher (encrypt)" << endl;
cipher(in, out, word1, nk, nb, nr);
cout << "round[" << nr << "].output ";
for(int i = 0; i < out.size(); i++){
    printf("%02x", out[i]);
}
cout << endl;
cout << endl;
cout << "invCipher (decrypt)" << endl;
invcipher(out, out2, word1, nk, nb, nr);
cout << "round[" << nr << "].ioutput ";
for(int i = 0; i < out2.size(); i++){
    printf("%02x", out2[i]);
}
cout << endl << endl;

nk = 8;
nr = 14;
//testing AES 256

keyExpansion(key2, word2, nk, nb, nr);
cout << "AES 256" << endl;
cout << "Cipher (encrypt)" << endl;
cipher(in, out, word2, nk, nb, nr);
cout << "round[" << nr << "].output ";
for(int i = 0; i < out.size(); i++){
    printf("%02x", out[i]);
}
cout << endl;
cout << endl;
cout << "invCipher (decrypt)" << endl;
invcipher(out, out2, word2, nk, nb, nr);
cout << "round[" << nr << "].ioutput ";
for(int i = 0; i < out2.size(); i++){
    printf("%02x", out2[i]);
}
cout << endl << endl;
}

//nk = 4 nb = 4 nr = 10
//nk = 6 nb = 4 nr = 12
//nk = 8 nb = 4 nr = 14