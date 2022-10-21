
/*
                                fileclient.cpp
                                Authors: Nathan Solomon and Daniel Williams

*/

#include "c150nastydgmsocket.h"
#include "c150dgmsocket.h"
#include "c150debug.h"
#include <fstream>
#include <dirent.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "c150grading.h"
#include <unistd.h>
#include "c150nastyfile.h"
#include <stdio.h>
#include <math.h>

// using std::ofstream;
using namespace std;          
using namespace C150NETWORK;   
// each Step describes a step in the file copy protocol
// each packet is assigned a step so that both the file 
// and client can avoid misentrepreting packets 
// that may come in delayed and get acidentally read in a future
// sock read
typedef enum Step {
    SENDFILENAME = 0,
    CONFIRMFILENAME,
    COPYFILE,
    ALL5PACKETS,
    SEND5PACKETS,
    ENDOFFILE,
    HASHCODE,
    SENDSTATUS,
    CONFIRMATION,
    ENDOFDIR,
    RESET
} Step;




struct Packet {
    
    char data[400]; // holds file data or messages used in the program

    Step currStep; // describes the packet's purpose in the program

    int fileNum;   // used to map file data packets with the respective file being copied

    int order;     // used in reordering out of order packets in groups of 5 being sent to server

    int dataSize;   // describes the size of meaningful data copied in the data member. used to send 
                   // the last packet of data in a file, so that the server does not write 400 bytes 
                   // of data if there is less than 400 bytes of data that needed to be sent in the last packet
};


// forward declarations
void checkAndPrintMessage(ssize_t readlen, char *buf, ssize_t bufferlen);
void setUpDebugLogging(const char *logname, int argc, char *argv[]);
void checkDirectory(char *dirname);
bool compareHashCodes(string clientHashCode, char* serverHashCode, C150DgmSocket* sock, string fileName, int numRetry, dirent *sourceFile, int fileNum);
void sendPacket(char* data, Step currStep, int fileNum, C150DgmSocket* sock, int order, int dataSize);
Packet makePacket(char* dataArr, Step currStep, int fileNum, int order, int dataSize);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                    Command line arguments
//
// The following are used as subscripts to argv, the command line arguments
// If we want to change the command line syntax, doing this
// symbolically makes it a bit easier.
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 




// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                           main program
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
    string SUCCESS = "success";
    string FAILURE = "failure";
    DIR* SOURCE;
    ofstream fileCheckResults;
int 
main(int argc, char *argv[]) {
    //
    //  DO THIS FIRST OR YOUR ASSIGNMENT WON'T BE GRADED!
    //
  
    GRADEME(argc, argv);

    //
    // Variable declarations
    //
    ssize_t readlen;              // amount of data read from socket
    // char serverHashCode[100];   // received message data

    //
    //  Set up debug message logging
    //
    setUpDebugLogging("pingclientdebug.txt",argc, argv);

    //
    // Make sure command line looks right
    //
    if (argc != 5) {
        fprintf(stderr,"Correct syntxt is: %s <server> <networknastiness> <filenastiness> <srcdir>\n", argv[0]);
        exit(1);
    }

    string serverName = argv[1];
    int networkNastiness = atoi(argv[2]);
    int fileNastiness = atoi(argv[3]);
    string srcdir = argv[4];
    struct dirent *sourceFile; 
    string clientHashVal = "";
    unsigned char obuf[20];
    int numFileRetries;
    string fileName;
    ifstream *t;
    stringstream *sBuffer;
    char hashVal[20];
    string globalReadMessageString;
    string sent5Packets = "sent 5 packets";
    const char* sent5PacketsArr = sent5Packets.c_str();
    ///
    // buffers used to interpret data sent from the server and read on the client side
    char tmpFileOpenConfirmMsg[sizeof(struct Packet)];
    char tmpServerMsg[sizeof(struct Packet)];
    char tmpserverConfirmation[sizeof(struct Packet)];
    char tmpENDServerConfirmation[sizeof(struct Packet)];

 
    
    fileCheckResults.open("fileCheckResults.txt");
 
    try {

        // Create the socket
        c150debug->printf(C150APPLICATION,"Creating C150DgmSocket");
        C150DgmSocket *sock = new C150NastyDgmSocket(networkNastiness);
        C150NastyFile *F = new C150NastyFile(fileNastiness);
        // Tell the DGMSocket which server to talk to
        sock -> setServerName((char*)serverName.c_str());  
        sock->turnOnTimeouts(3000);

    
        
      
    
        checkDirectory((char*)srcdir.c_str());
        SOURCE = opendir(srcdir.c_str());
       if (SOURCE == NULL) {
            fprintf(stderr,"Error opening target directory %s \n", srcdir.c_str());     
            exit(8);
        }

    
        string path;
        int currFileNum = 0;
        // iterate through the file directory
        while ((sourceFile = readdir(SOURCE)) != NULL) {
           
            clientHashVal = "";
            // skip the . and .. names
            if ((strcmp(sourceFile->d_name, ".") == 0) || (strcmp(sourceFile->d_name, "..")  == 0 )) {
                 continue;  
            }
            currFileNum++;
           
            path = srcdir + "/" + sourceFile->d_name;
            t = new ifstream(path);
            sBuffer = new stringstream;
            *sBuffer << t->rdbuf();
            SHA1((const unsigned char *)sBuffer->str().c_str(), (sBuffer->str()).length(), obuf);
            // creating a hash value from the current file that will be copied to the server.
            // used to ensure correctness or failure after the file has been copied
            for (int i = 0; i < 20; i++)
            {
                sprintf(hashVal,"%02x",(unsigned int) obuf[i]);
                string stringHashVal(hashVal);
                clientHashVal += stringHashVal;
            }
            bool isFileSendRetry = true;
            bool isEndToEndFailed = false;
            numFileRetries = 1;
            while (isFileSendRetry) {
                F->fopen((const char*)path.c_str(), "r");

             
                fileName = string(sourceFile->d_name);

                *GRADING << "File: " << fileName << ", beginning transmission, attempt " << numFileRetries << endl; 


                // c150debug->printf(C150APPLICATION,"\n%s: Writing message: \"%s\"", argv[0], fileName.c_str());
                // wait for a confirmation from the server that it has opened the file with the filename the client has sent
                bool isFileOpenConfirmReceived = false;
                // while the client hasn't yet received the confirmation message of file opening,
                // keep sending the file name to the server
                while (!isFileOpenConfirmReceived) {
                    sendPacket(sourceFile->d_name, SENDFILENAME, currFileNum, sock, -1, -1);
                    sock->read(tmpFileOpenConfirmMsg, sizeof(struct Packet));
                    if(sock->timedout()) {
                        continue;
                    }
                    Packet *serverFileOpenPacket;
                    serverFileOpenPacket = (Packet*)tmpFileOpenConfirmMsg;
                    // if  we finally receive the confirmation message, set a boolean to end this loop
                    // on the next iteraton
                    if(serverFileOpenPacket->currStep == CONFIRMFILENAME and serverFileOpenPacket->fileNum == currFileNum) {
                        isFileOpenConfirmReceived = true;
                    }
                    // if you get a delayed hash code from the server, compare the hash codes and send the result of the comparison
                    if(serverFileOpenPacket->currStep == HASHCODE and serverFileOpenPacket->fileNum == currFileNum and isEndToEndFailed) {
                        compareHashCodes(clientHashVal, (char*)globalReadMessageString.c_str(), sock, string(sourceFile->d_name), 1, sourceFile, currFileNum);
                    }
                }
                 bool endOfFile = false;
                 string serverHashCode;

                char buffer[400];
                char tmpBuf[200];
                int counter = 0;
                // main loop for copying all the bytes in a file until reaching end of the file
                while (!endOfFile) {
                    int numCharsRead = 1;
                        // while 5 packets (2000 characters) have not been sent yet and you have
                        // not reached the end of the file, keep reading the file
                        while((counter <= 2000) and numCharsRead != 0) {
                            numCharsRead = F->fread(tmpBuf, 1, 200); 
                            // break if you reach the end of the file at any time
                            if(numCharsRead == 0) {
                                break;
                            }
                            string prevString = string(tmpBuf);
                            int numSameReads = 0;
                            // handling for file-reading nastiness. The same 200 
                            // characters are repeatedly read. The same sequence 
                            // of characters must be read consecutively to ensure 
                            // that the read characters were not manipulated
                            while(numSameReads != 10) {
                                F->fseek(numCharsRead * -1, SEEK_CUR);
                                F->fread(tmpBuf, 1, numCharsRead);
                                if(prevString == string(tmpBuf)) {
                                    numSameReads++;
                                }
                                else {
                                    numSameReads = 0;
                                }
                                prevString = string(tmpBuf);
                            }
                            // copy the 200 read characters (now very likely to be correct)
                            // to a buffer that is used to populate the data that a packet holds
                            memcpy(buffer + counter % 400,tmpBuf, numCharsRead);
                            counter+=numCharsRead;
                            // if we have enough characters read to send a packet
                            if ((counter % 400) == 0) {
                                c150debug->printf(C150APPLICATION,"%s: sending SINGLE packets", argv[0]);
                                // send a packet with the characters read
                                sendPacket(buffer, COPYFILE, currFileNum, sock, (counter / 400) - 1, -1);
                                // if 5 characters have been read, tell the server that the client has 
                                // sent 5 packets and wait for a confirmation that it received all 5 (or a 
                                // message saying that it did not receive all 5 packets)
                                if (counter == 2000) {
                                    counter = 0;
                                    c150debug->printf(C150APPLICATION,"%s: sending 5 packets", argv[0]);
                                    sendPacket((char*)sent5PacketsArr, ALL5PACKETS, currFileNum, sock, -1, -1);
                                    break;
                                }
                            }
                        }
                    // case where the end of a file has been reached
                    if(numCharsRead == 0) {
                        endOfFile = true;
                        
                        int packetNum = ceil(counter / 400);
                        // tell the server that the end of file has been reached, along with the remaining data
                        // that may not be 400 bytes long like the other packets. The length of the data held
                        // in the last packet is counter % 400
                        sendPacket(buffer, ENDOFFILE, currFileNum, sock, packetNum, counter % 400);
                        *GRADING << "File: " << fileName << " transmission complete, waiting for end-to-end check, attempt " << numFileRetries << endl;
                    }
                    
                    bool receivedSend5Packets = false;
                    // listen for the message from the server that it received the 5 packets the client just sent
                    while (!receivedSend5Packets) {
                        // listen for a SENDPACKETS message
                        sock->read(tmpServerMsg, sizeof(struct Packet));
                         if (sock -> timedout()) {
                            if (endOfFile) {
                                // if there is a time out and you have told the client you are at the end of the 
                                // file, then re-send the end of file message
                                sendPacket(buffer, ENDOFFILE, currFileNum, sock, -1, counter % 400);

                            } 
                            else {
                                // if there is a timeout and the client has not received a message from the server 
                                // to send the NEXT 5 packets, tell the server again that the client has sent 5 packets
                                sendPacket((char*)sent5PacketsArr, ALL5PACKETS, currFileNum, sock, -1, -1);
                            }
                            continue;
                         }

                        Packet *serverFileOpenPacket = (Packet*)tmpServerMsg;
                        //cleaning message from server in case it is a hash code
                        char* readMessage = serverFileOpenPacket->data;
                        readMessage[strlen(readMessage)] = '\0';
                        string readMessageString(readMessage);
                        cleanString(readMessageString);
                        serverHashCode = readMessageString;
                        globalReadMessageString = readMessageString;

                        
                        if(endOfFile and serverFileOpenPacket->currStep == SEND5PACKETS and serverFileOpenPacket->fileNum == currFileNum and readMessageString == "Resend end of file packets") {
                            // re-send the previous 5 packets if the server asks for them (which means an error occured somewhere in the 
                            // transmission of 5 packets)
                            F->fseek((counter * -1), SEEK_CUR);
                            counter = 0;
                            endOfFile = false;
                            break;
                        }

                        if(endOfFile and serverFileOpenPacket->currStep == SEND5PACKETS and serverFileOpenPacket->fileNum == currFileNum) {
                            continue;
                        }

                        if (serverFileOpenPacket->currStep == SEND5PACKETS and serverFileOpenPacket->fileNum == currFileNum) {
                            if (string(serverFileOpenPacket->data) == "Resend 5") {
                                 F->fseek(-2000, SEEK_CUR);
                            }
                            // the server has successfully received all 5 packets and wants the next 5 packets. So, break out 
                            // of this loop on the next iteration and continue reading the file
                            receivedSend5Packets = true;
                        }
                        // if the server has sent the client a hash code of the file it has copied over the network, compare 
                        // it with the true SHA1 value of the file held in the source directory on the client side
                        if(endOfFile and serverFileOpenPacket->currStep == HASHCODE and serverFileOpenPacket->fileNum == currFileNum) {
                            receivedSend5Packets = true;
                            // if the hash code comparison fails (the copied file was not copied correctly), then retry sending the file again
                            // and repeat the entire file copying process for the same file
                            if (!compareHashCodes(clientHashVal, (char*)readMessageString.c_str(), sock, string(sourceFile->d_name), 1, sourceFile, currFileNum)) {
                                isEndToEndFailed = true; 
                                *GRADING << "File: " << fileName << "end-to-end check failed, attempt " << numFileRetries << endl;
                                numFileRetries ++;
                            } else {
                                // do not repeat the file copy process for the same file if the hash code comparison suceeds
                                isFileSendRetry = false;
                                *GRADING << "File: " << fileName << " end-to-end check succeeded, attempt " << numFileRetries << endl;
                            }
                        }
                    }
                }
                
                
                
                int numRetries = 0;
                // listening for confirmation from the server for its knowledge about the success or failure of the end-to-end check
                    while(!isEndToEndFailed) {
                    
                        readlen = sock -> read(tmpserverConfirmation, sizeof(struct Packet));

                        if(sock -> timedout()) {
                             // perform 5 retries for listening for the confirmation from the server until giving up
                            if (numRetries == 5) {
                                throw C150NetworkException("the network is down");
                            }
                            numRetries++;
                            // if no response from the server is heard, resend the result of the hash code comparison
                            compareHashCodes(clientHashVal, (char*)serverHashCode.c_str(), sock, string(sourceFile->d_name), 1, sourceFile, currFileNum);
                            continue;
                        }
                       
                        Packet *serverConfirmationPacket = (Packet*)tmpserverConfirmation;
                        char* serverConfirmation = serverConfirmationPacket->data;
                        serverConfirmation[strlen(serverConfirmation)] = '\0';
                        string serverConfirmationString(serverConfirmation);
                        cleanString(serverConfirmationString);
                        // if it does not time out
                        // ignore any message that is not a confirmation message and continue reading
                        if (serverConfirmationPacket->currStep != CONFIRMATION or serverConfirmationPacket->fileNum != currFileNum) {
                                continue;
                        }
                        // exit this read loop if we know now that we have received a confirmation message
                        if (readlen != 0) {
                            break;
                        }
                    }
                F->fclose();
            }
            delete t;
            delete sBuffer;   
        }
       // tell the server that the end of the directory has been reached
        string sampleMsg = "ENDOFDIR";
        const char* sampleMsgArr = sampleMsg.c_str();
        sendPacket((char*)sampleMsgArr, ENDOFDIR, 0, sock, -1, -1);
        bool isResetConfirmed = false;
        while(!isResetConfirmed) {
            // listen for a message from the server that the server is ready to read another directory
            readlen = sock -> read(tmpENDServerConfirmation, sizeof(struct Packet));
            if(sock -> timedout()) {
                // if a timeout occurs, resend the message saying that you have reached the end of the directory
                sendPacket((char*)sampleMsg.c_str(), ENDOFDIR, 0, sock, -1, -1);
                continue;
            }
            else {
                Packet *serverENDConfirmationPacket = (Packet*)tmpENDServerConfirmation;
                // ignore any message that is not a confirmation from the server
                if (serverENDConfirmationPacket->currStep != RESET) {
                        continue;
                }
                isResetConfirmed = true;
            }

        }
        closedir(SOURCE);
        // fileCheckResults.close();
    }

    catch (C150NetworkException& e) {
        // Write to debug log
        c150debug->printf(C150ALWAYSLOG,"Caught C150NetworkException: %s\n",
                          e.formattedExplanation().c_str());
        // In case we're logging to a file, write to the console too
        cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation()\
                        << endl;
    }

    return 0;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                         comapreHashCodes
//
//      Purpose: compares the SHA1 hash code sent from the server with
//               the garunteed-to-be-true hash code created from the 
//               file hashed from the source directory on the client side.
//               Sends the result of the hash code comparison to the server
//
//      Arguments: the hash code generated on the client side, the hash code 
//                 created on the server side, the socket used, the current file name
//                and the number of retries done so far(for debugging purposes), 
//               the source file name, and the current number of the file in the source directory
//               
//      Return: the result of the hash code comparison as a boolean value
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
bool compareHashCodes(string clientHashCode, char* serverHashCode, C150DgmSocket* sock, string currFile, int numRetry, dirent *sourceFile, int currFileNum) {
    if(string(serverHashCode) == clientHashCode) {
        
        string statusMessage = SUCCESS;
        sendPacket((char*)SUCCESS.c_str(), SENDSTATUS, currFileNum, sock, -1, -1);
        return true;
    }
    else {
    
        c150debug->printf(C150APPLICATION,"%s: Writing message: \"%s\"", "fileclient", FAILURE.c_str());
        sendPacket((char*)FAILURE.c_str(), SENDSTATUS, currFileNum, sock, -1, -1);
        return false;
    }
     
}
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                         sendPacket
//
//      Purpose: sends a packet to the server
//
//      Arguments: the hash code generated on the client side, the hash code 
//                 created on the server side, the socket used, the current file name
//                and the number of retries done so far(for debugging purposes), 
//               the source file name, and the current number of the file in the source directory
//
//      Return: none
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
void sendPacket(char* data, Step currStep, int fileNum, C150DgmSocket* sock, int order, int dataSize) {
        Packet newPacket = makePacket((char*)data, currStep, fileNum, order, dataSize);
        char * newPacketArr = (char *)&newPacket;
        sock -> write(newPacketArr, sizeof(newPacket)); 
}

void
checkAndPrintMessage(ssize_t readlen, char *msg, ssize_t bufferlen) {
 
    if (readlen == 0) {
        throw C150NetworkException("Unexpected zero length read in client");
    }

    // DEFENSIVE PROGRAMMING: we aren't even trying to read this much
    // We're just being extra careful to check this
    if (readlen > (int)(bufferlen)) {
        throw C150NetworkException("Unexpected over length read in client");
    }

    if(msg[readlen-1] != '\0') {
        throw C150NetworkException("Client received message that was not null terminated");     
    };

    string s(msg);
    cleanString(s);

    // Echo the response on the console

    c150debug->printf(C150APPLICATION,"PRINTING RESPONSE: Response received is \"%s\"\n", s.c_str());
    printf("Response received is \"%s\"\n", s.c_str());

}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
 
void setUpDebugLogging(const char *logname, int argc, char *argv[]) {

    ofstream *outstreamp = new ofstream(logname);
    DebugStream *filestreamp = new DebugStream(outstreamp);
    DebugStream::setDefaultLogger(filestreamp);

    c150debug->setPrefix(argv[0]);
    c150debug->enableTimestamp(); 

    c150debug->enableLogging(C150APPLICATION | C150NETWORKTRAFFIC | 
                             C150NETWORKDELIVERY); 
}

void
checkDirectory(char *dirname) {
  struct stat statbuf;  
  if (lstat(dirname, &statbuf) != 0) {
    fprintf(stderr,"Error stating supplied source directory %s\n", dirname);
    exit(8);
  }

  if (!S_ISDIR(statbuf.st_mode)) {
    fprintf(stderr,"File %s exists but is not a directory\n", dirname);
    exit(8);
  }
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                         makePacket
//
//      Purpose: creates a packet object to be sent to teh server
//
//      Arguments: the data sent with the packet, the current purpose 
///                of the packet denoted by "currStep", the file number
//                 in the directory, the order of the packet in 1-5 
//                 when sent as a group of 5 packets, and the size of the
//                 data being sent 
//
//      Return: the packet object
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Packet makePacket(char* dataArr, Step currStep, int fileNum, int order, int dataSize) {
    Packet newPacket;
    memcpy(newPacket.data, dataArr, strlen(dataArr) + 1);
    newPacket.currStep = currStep;
    newPacket.fileNum = fileNum;
    newPacket.order = order;
    newPacket.dataSize = dataSize;
    return newPacket;
}
