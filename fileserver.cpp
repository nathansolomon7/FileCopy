/*
                                fileserver.cpp
                                Authors: Nathan Solomon and Daniel Williams

*/
#include "c150nastydgmsocket.h"
#include "c150debug.h"
#include <fstream>
#include <cstdlib> 
#include <dirent.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "c150grading.h"
#include "c150nastyfile.h"

using namespace C150NETWORK; 

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
    char data[400];
    Step currStep;
    int fileNum;
    int order;
    int dataSize;
};

string SUCCESS = "success";
string FAILURE = "failure";
void setUpDebugLogging(const char *logname, int argc, char *argv[]);
void checkDirectory(char *dirname);
void createHashCode(string path, C150DgmSocket *sock, int currFileNum);
void sendPacket(string data, Step currStep, int fileNum, C150DgmSocket* sock, int order);
Packet makePacket(char* dataArr, Step currStep, int fileNum, int order);
string readMessage(char* buffer, Packet* p, C150DgmSocket* sock);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                           main program
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
 
int
main(int argc, char *argv[])
{
     GRADEME(argc, argv);

    //
    // Variable declarations 
    //
    int networkNastiness;  
    string fileNameString;
    int fileNastiness;
    int numFileRetries;
    string targetDirectory;
    DIR *TARGET;                // Unix descriptor for target
	string builtHashVal = "";  // hashcode from server of file
    char tmpFileNamePacket[sizeof(struct Packet)];
    char tmpCurrFile[sizeof(struct Packet)];
    char tmpStatusPacket[sizeof(struct Packet)];
    
    // Check command line and parse arguments
    if (argc != 4)  {
        fprintf(stderr,"Correct syntax is: %s <network nastiness> <file nastiness> <targetDIR>\n", argv[0]);
        exit(1);
    }

    if (strspn(argv[1], "0123456789") != strlen(argv[1])) {
        fprintf(stderr,"Network Nastiness %s is not numeric\n", argv[1]);     
        fprintf(stderr,"Correct syntxt is: %s <nastiness_number>\n", argv[0]);     
        exit(4);
    }

    if (strspn(argv[2], "0123456789") != strlen(argv[2])) {
        fprintf(stderr,"File Nastiness %s is not numeric\n", argv[1]);     
        fprintf(stderr,"Correct syntxt is: %s <file_nastiness>\n", argv[0]);     
        exit(4);
    }


    networkNastiness = atoi(argv[1]);   
    fileNastiness = atoi(argv[2]);   
    targetDirectory = argv[3];
    setUpDebugLogging("pingserverdebug.txt",argc, argv);
    c150debug->setIndent("    ");

    try{
        //preparing for file IO with error checking
        checkDirectory((char*)targetDirectory.c_str()); 
        TARGET = opendir(argv[3]);
        if (TARGET == NULL) {
            fprintf(stderr,"Error opening target directory %s \n", argv[3]);     
            exit(8);
        }

        c150debug->printf(C150APPLICATION,"Creating C150NastyDgmSocket(nastiness=%d)",  networkNastiness);
        C150DgmSocket *sock = new C150NastyDgmSocket(networkNastiness);
        C150NastyFile * F = new C150NastyFile(fileNastiness);
        
        
        int currFileNum = 0;
        bool incrementFileNum = true;
        while(1) {
            // checks if the program should continue to the next file
            if (incrementFileNum) {
                currFileNum++;
                numFileRetries = 1;
            }
            
            bool isFileReceived = false;
            bool isStatusReceived = false;
            string filePath;
            string path;

            //
            //  Loop receiving the file's name and its content
            //
            while(!isFileReceived) {
                incrementFileNum = true;
                
                Packet *fileNamePacket = (Packet*)tmpFileNamePacket;
                fileNameString = readMessage(tmpFileNamePacket, fileNamePacket, sock);

                // handling for when an end of directory packet is wrongly sent by the server -- indicating 
                // that the server never received the reset packet
                if (fileNamePacket->currStep  == ENDOFDIR) {
                    string sampleMsg = "RESET";
                    currFileNum = 1;
                    sendPacket(sampleMsg, RESET, 0, sock, -1);
                    continue;
                }

                // handling for when an send status packet is wrongly sent by the server  -- indicating that the sever
                // never received the confirmation packet
                if (fileNamePacket->currStep == SENDSTATUS and fileNamePacket->fileNum == currFileNum - 1) {
                    sendPacket("re-sending the confirmation packet", CONFIRMATION, currFileNum - 1, sock, -1);
                    continue;
                }

                // handles for if the packet read is anything but what the program intends for and it is skipped
                if (fileNamePacket->currStep != SENDFILENAME or fileNamePacket->fileNum != currFileNum) {
                    continue;
                }
                
                //  at this point the program assumes that the filename has been received
                isFileReceived = true;
                filePath = targetDirectory + "/" + fileNameString + ".tmp";
                *GRADING << "File: " << fileNameString << " starting to receive file" << endl;

                if(F->fopen((const char*)filePath.c_str(), "w") == NULL) {
                    cerr << "could not open file" << endl;
                    exit(1);
                }

                // writes to the client, informing it that the filename has been received
                sendPacket("file " + fileNameString + ".tmp " + "has been opened", CONFIRMFILENAME, currFileNum, sock, -1);

                bool endOfFile = false;            
                int packetCount = 0;
                char buffer[2000];
                bool all5LastPacket = false;
                int counter = 0;
                bool isPrevPacketAll5 = false;

                //
                // loop handling the logic of receiving file data packets
                //
                while (!endOfFile) {
                    Packet *dataPacket = (Packet*)tmpCurrFile;
                    string dataPacketData = readMessage(tmpCurrFile, dataPacket, sock);
                    counter ++;

                    // handles for if the client did not get the confirmation of server opening the file
                    if (dataPacket->currStep == SENDFILENAME and dataPacket->fileNum == currFileNum) {
                        sendPacket("file " + fileNameString + ".tmp " + "has been opened", CONFIRMFILENAME, currFileNum, sock, -1);
                    }


                    // handles for if the last packet was an ALL5PACKET 
                    if (all5LastPacket and dataPacket->currStep == COPYFILE and dataPacket->fileNum == currFileNum) {
                        packetCount = 0;
                        all5LastPacket = false;
                    }

                    //handles for if the packet received is a copyfile packet
                    if (dataPacket->currStep == COPYFILE and dataPacket->fileNum == currFileNum) {
                        memcpy((void*)(buffer + (dataPacket->order * 400)), dataPacket->data, 400);
                        packetCount++;
                    }

                    // handles for if the packet received is a ALL5PACKET meaning that the client has sent 5 file packets
                    if (dataPacket->currStep == ALL5PACKETS and dataPacket->fileNum == currFileNum) {
                        all5LastPacket = true;
                        // if the server received the right amount of packets
                        if(packetCount == 5 ) { 
                            sendPacket("Send NEXT 5", SEND5PACKETS, currFileNum, sock, -1);
                            
                            // handling for duplicate ALL5PACKETS
                            if (!isPrevPacketAll5) {
                                F->fwrite(buffer, 1, sizeof(buffer));
                                memset(buffer, 0, 2000);
                            }
                      
                        }
                        else { // handles for if the server received the wrong amount of packets
                            packetCount = 0;
                            sendPacket("Resend 5", SEND5PACKETS, currFileNum, sock, -1);
                        }
                        isPrevPacketAll5 = true;
                    }
                    else if (dataPacket->currStep != ALL5PACKETS and dataPacket->fileNum == currFileNum) { // 
                        isPrevPacketAll5 = false;
                    }

                    // handles for if the end of file indicator packet is recieved
                    if (dataPacket->currStep == ENDOFFILE and dataPacket->fileNum == currFileNum) {
                        
                        
                        if(packetCount == 5) {
                            packetCount = 0;
                        }

                        // handles for when the program has the wrong number of packets
                        if (packetCount != dataPacket->order) {
                            sendPacket("Resend end of file packets", SEND5PACKETS, currFileNum, sock, dataPacket->order);
                            all5LastPacket = true;
                            continue;
                        }
                        endOfFile = true;
                      
                        //handles for when the buffer is not full
                        if(packetCount != 5) {
                             memcpy((void*)(buffer + ((packetCount) * 400)), dataPacket->data, dataPacket->dataSize);
                            F->fwrite(buffer, 1, ((packetCount) * 400) + dataPacket->dataSize);
                        }
                        else if (dataPacket->dataSize != 0){ // if the program has already sent 5 packets, we dont want the program to overwrite the buffer containing valid data
                            F->fwrite(dataPacket->data, 1, dataPacket->dataSize);
                            
                        }
                       
                    }
                }
                F->fclose();
                
            }
                //end to end check is starting
                *GRADING << "File: " << fileNameString << " transmission complete, waiting for end-to-end check, attempt " << numFileRetries << endl;
                // creates and sends hashcode from newly copied file to the client
                createHashCode(filePath, sock, currFileNum);
                
                //
                // loop receiving status after sending hashcode to client
                //
                while(!isStatusReceived) {
                    // if you get "a file has been received from the server" message, go back to the top
                    // of this loop 
                    Packet *statusPacket = (Packet*)tmpStatusPacket;
                    
                    string statusString = readMessage(tmpStatusPacket, statusPacket, sock);

                    //handles for if the program is at the end of the directory
                    if (statusString == (SUCCESS + " final") or statusString == (FAILURE + " final")) {
                        currFileNum = 0;
                    }

                    // handles for if the client receives a packet that isn't a status packet
                    if(statusPacket->currStep != SENDSTATUS) {
                        createHashCode(filePath, sock, currFileNum);
                    }
                    else { // handles for when the status is received by the server
                         isStatusReceived = true;
                         if(statusString == "success") {
                            *GRADING << "File: " << fileNameString  << " end-to-end check succeeded" << endl;
                             rename(filePath.c_str(), filePath.substr(0, filePath.length() - 4).c_str());
                         }
                         else {
                            *GRADING << "File: " << fileNameString << " end-to-end check failed" << endl;
                            incrementFileNum = false;
                            numFileRetries ++;
                            break;
                             
                        }

                        //sends confirmaiton of status to the client
                        string serverConfirmationMsg = "server confirmed " + statusString;
                        c150debug->printf(C150APPLICATION,"sending confirmation msg \" %s\"\n", serverConfirmationMsg.c_str());
                        sendPacket(serverConfirmationMsg, CONFIRMATION, currFileNum, sock, -1);
                   }
                }
            }
        closedir(TARGET);
    } 
    catch (C150NetworkException& e) {
        // Write to debug log
        c150debug->printf(C150ALWAYSLOG,"Caught C150NetworkException: %s\n",
                          e.formattedExplanation().c_str());
        cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation()\
                        << endl;
    }
    return 4;
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
//                         createHashCode
//
//      Purpose: creates a hashcode using SHA and sends this value to the client
//
//      Arguments: a path denoting the path to the file that will be hashed,
//                 a socket to facilitate the connection with teh client,
//                 and an integer represent the number file we are on
//
//      Return: N/A
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
void createHashCode(string path, C150DgmSocket *sock, int currFileNum) {
    char hashVal[20];
    unsigned char obuf[20];
    ifstream *t;
    stringstream *buffer;
    string builtHashVal = "";

    t = new ifstream(path);
    buffer = new stringstream;
    *buffer << t->rdbuf();
    SHA1((const unsigned char *)buffer->str().c_str(), (buffer->str()).length(), obuf);

    for (int i = 0; i < 20; i++)
    {
        sprintf(hashVal,"%02x",(unsigned int) obuf[i]);
        string stringHashVal(hashVal);
        builtHashVal += stringHashVal;
    }
    char* builtHashValArr = (char*)builtHashVal.c_str();

    c150debug->printf(C150APPLICATION,"Responding with message=\"%s\"", builtHashValArr);
    
    sendPacket(string(builtHashValArr), HASHCODE, currFileNum, sock, -1);
    delete t;
    delete buffer;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                     setUpDebugLogging
//
//        For COMP 150-IDS, a set of standards utilities
//        are provided for logging timestamped debug messages.
//        You can use them to write your own messages, but 
//        more importantly, the communication libraries provided
//        to you will write into the same logs.
//
//        As shown below, you can use the enableLogging
//        method to choose which classes of messages will show up:
//        You may want to turn on a lot for some debugging, then
//        turn off some when it gets too noisy and your core code is
//        working. You can also make up and use your own flags
//        to create different classes of debug output within your
//        application code
//
//        NEEDSWORK: should be factored and shared w/fileclient
//        NEEDSWORK: document arguments
//
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


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                          makePacket
//
//      Purpose: creates a Packet with the given arguments
//
//      Arguments: char array denoting the data field of the packet,
//                 an enum representing the current step of the packet
//                 an integer representing the number file that the packet 
//                 is associated with, and the order of the packet
//
//      Return: returns a Packet
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

Packet makePacket(char* dataArr, Step currStep, int fileNum, int order) {
    Packet newPacket;
    memcpy(newPacket.data, dataArr, strlen(dataArr) + 1);
    newPacket.currStep = currStep;
    newPacket.fileNum = fileNum;
    newPacket.order = order;
    return newPacket;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                         sendPacket
//
//      Purpose: utilizes makePacket() to send a packet 
//
//      Arguments: a string representing the data field of the packet,
//                 an enum representing the current step of the packet,
//                 an integer representing the file number that the packet is 
//                 associated with, a socket to facilitate the connection with 
//                 the client, and an integer representing the ordr of te packet
//
//      Return: N/A
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
void sendPacket(string data, Step currStep, int fileNum, C150DgmSocket* sock, int order) {
        Packet newPacket = makePacket((char*)data.c_str(), currStep, fileNum, order);
        char * newPacketArr = (char *)&newPacket;
        sock -> write(newPacketArr, sizeof(newPacket)); 
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                         readMessage
//
//      Purpose: reads data from socket 
//
//      Arguments: char array representing the data to be read from the client,
//                 a Packet that the buffer will be casted to, and the sock
//                 to facilitate the connection with the client
//
//      Return: returns a string representing the data field of read packet
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
string readMessage(char* buffer, Packet* p, C150DgmSocket* sock) {
    sock -> read(buffer, sizeof(struct Packet));
    p = (Packet*)buffer;
    char* readMessage = p->data;
    readMessage[strlen(readMessage)] = '\0';
    string readMessageString(readMessage);
    cleanString(readMessageString);
    return readMessageString;
}




