#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <bitset>
#include <iomanip>

using namespace std;

const int BLOCK_SIZE = 16;
const char PADDING_BYTE = 0x81;

string convertToASCII(string characters){ //did not need this method but better safe then sorry
    string ASCIIconverted;

    for(char character : characters){
        ASCIIconverted += (static_cast<int>(character)); //converts characters to ASCII using int type casting
    }

    return ASCIIconverted;
}

string xorBlockString(string noXOR, string key){
    int counter = 0;
    int numLoops = noXOR.size() / key.size();
    string xorString = "";
    //loops based on how many blocks of 16 bytes exist and xors every block to 16 byte to key
    for(int i = 0; i < numLoops; i++){
        for(size_t j = 0; j < key.size(); j++){
            xorString += static_cast<char>(noXOR[counter] ^ key[j]);
            counter++;
        }
    }
    return xorString;
}

string padBlock(string noPad, string key){
    int padding;
    //checks if unpadded string is bigger than key meaning next block needs to be padded, else first string is padded
    if(noPad.size() > key.size()){
        int x = noPad.size() % key.size();
        padding = 16 - x;
    }else{
        padding = key.size() - noPad.size();
    }
    
    string returnPad = noPad;
    //adds 0x81 pad to return string
    for(int i = 0; i < padding; i++){
        returnPad += PADDING_BYTE;          //use pop back for decrypt 
    }

    return returnPad;
}

string unpadBlock(string data){
    string pad_data = data;
    int i = pad_data.length() - 1;
 
    while(pad_data[i] == PADDING_BYTE){
        pad_data.pop_back();
        i--;
    }
    return pad_data;
}

string swapData(string data, string key){
    int startData = 0;
    int end = data.size() - 1;
    int startKey = 0;
    string swappingData = data;
    string swappingKey = key;
    
    while(startData < end){
        if(startKey < (int)key.size()){
            if(swappingKey[startKey] % 2 == 1){
                char swap = swappingData[startData];
                swappingData[startData] = swappingData[end];
                swappingData[end] = swap;
                startData++;
                end--;
            }else{
                startData++;
            }
            startKey++;
        }else{
            startKey = 0;
        }
    }
    return swappingData;
}


// Function to perform block cipher encryption
void blockCipherEncrypt(string data, string key, string output) {
    string dataASCII = convertToASCII(data);
    string keyASCII = convertToASCII(key);

    //pads data to make 16 byte blocks
    string paddingData = padBlock(dataASCII, keyASCII);
    string xorData = xorBlockString(paddingData, keyASCII);
    string swappedData = swapData(xorData, keyASCII);
  
    ofstream outputFile(output, ios::binary);

    // Write the string as bytes to the output file
    outputFile.write(swappedData.c_str(), swappedData.size());

    // Close the output file
    outputFile.close();


}

// Function to perform block cipher decryption
void blockCipherDecrypt(string data, string key, string output) {
    string encrypt_data = data;
    string key_data = key;

    string unswapped_data = swapData(encrypt_data, key_data);
    string decrypted_data = xorBlockString(unswapped_data, key_data);
    string unpadded_data = unpadBlock(decrypted_data);

    ofstream outputFile(output, ios::binary);

    // Write the string as bytes to the output file
    outputFile.write(unpadded_data.c_str(), unpadded_data.size());

    // Close the output file
    outputFile.close();
}


// Function to perform stream cipher encryption/decryption
void streamCipher(string data, string key, string output) {
    string newKey;
    while (newKey.size() < data.size()) {
        for(size_t i = 0; i < key.size(); i++){
            newKey += key[i];
        }
    }
    string ASCIIdata = convertToASCII(data);
    string ASCIIkey = convertToASCII(newKey);
   
    string asciiString;
    int counter = 0;

    for (auto it = data.begin(), end = data.end(); it != end; ++it){
        asciiString += static_cast<char>(ASCIIdata[counter] ^ ASCIIkey[counter]);
        counter++;
    }
    
    ofstream outputFile(output, ios::binary);

    // Write the string as bytes to the output file
    outputFile.write(asciiString.c_str(), asciiString.size());

    // Close the output file
    outputFile.close();

}


int main(int argc, char* argv[]) {
   
    if (argc != 6) {
        cerr << "Usage: " << argv[0] << " <B|S> <input_file> <output_file> <keyfile> <E|D>" << endl;
        return 1;
    }

    char mode = argv[1][0];
    string inputFile = argv[2];
    string outputFile = argv[3];
    string keyfile = argv[4];
    char operation = argv[5][0];

    // Read the key from the keyfile
    ifstream keyStream(keyfile.c_str(), ios::binary);

    if(!keyStream.is_open()){
        cerr << "key file does not exist" << endl;
        exit(1);
    }

    vector<char> key((istreambuf_iterator<char>(keyStream)), (istreambuf_iterator<char>()));

    // Read the input data from the input file
    ifstream inputStream(inputFile.c_str(), ios::binary);

    if(!inputStream.is_open()){
        cerr << "input file does not exist" << endl;
        exit(1);
    }

    vector<char> inputData((istreambuf_iterator<char>(inputStream)), (istreambuf_iterator<char>()));
    
    string newKey(key.begin(), key.end());
    string newData(inputData.begin(), inputData.end());

    // Perform encryption or decryption based on the mode and operation
    if (mode == 'B') {
        if (operation == 'E') {
            blockCipherEncrypt(newData, newKey, outputFile);
        } else if (operation == 'D') {
            blockCipherDecrypt(newData, newKey, outputFile);
        }
    } else if (mode == 'S') {
        streamCipher(newData, newKey, outputFile);
    } else {
        cerr << "Invalid mode: " << mode << endl;
        return 1;
    }

    return 0;
}
