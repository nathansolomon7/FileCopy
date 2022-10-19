// --------------------------------------------------------------
//
//                        fileclient.cpp
//
//        Author: Noah Mendelsohn         
//   
//
//        This is a simple client, designed to illustrate use of:
//
//            * The C150DgmSocket class, which provides 
//              a convenient wrapper for sending and receiving
//              UDP packets in a client/server model
//
//            * The c150debug interface, which provides a framework for
//              generating a timestamped log of debugging messages.
//              Note that the socket classes described above will
//              write to these same logs, providing information
//              about things like when UDP packets are sent and received.
//              See comments section below for more information on 
//              these logging classes and what they can do.
//
//
//        COMMAND LINE
//
//              pingclient <servername> <msgtxt>
//
//
//        OPERATION
//
//              pingclient will send a single UDP packet
//              to the named server, and will wait (forever)
//              for a single UDP packet response. The contents
//              of the packet sent will be the msgtxt, including
//              a terminating null. The response message
//              is checked to ensure that it's null terminated.
//              For safety, this application will use a routine 
//              to clean up any garbage characters the server
//              sent us, (so a malicious server can't crash us), and
//              then print the result.
//
//              Note that the C150DgmSocket class will select a UDP
//              port automatically based on the user's login, so this
//              will (typically) work only on the test machines at Tufts
//              and for COMP 150-IDS who are registered. See documention
//              for the comp150ids getUserPort routine if you are 
//              curious, but you shouldn't have to worry about it.
//              The framework automatically runs on a separate port
//              for each user, as long as you are registerd in the
//              the student port mapping table (ask Noah or the TAs if
//              the program dies because you don't have a port).
//
//        LIMITATIONS
//
//              This version does not timeout or retry when packets are lost.
//
//
//       Copyright: 2012 Noah Mendelsohn
//     
// --------------------------------------------------------------

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

// using std::ofstream;
using namespace std;          // for C++ std library
using namespace C150NETWORK;  // for all the comp150 utilities 
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
    // is this a filename or status?
    char data[400];
    Step currStep;
    int fileNum;
    int order;
};


// forward declarations
void checkAndPrintMessage(ssize_t readlen, char *buf, ssize_t bufferlen);
void setUpDebugLogging(const char *logname, int argc, char *argv[]);
void checkDirectory(char *dirname);
bool compareHashCodes(string clientHashCode, char* serverHashCode, C150DgmSocket* sock, string fileName, int numRetry, dirent *sourceFile, int fileNum);
void sendPacket(string data, Step currStep, int fileNum, C150DgmSocket* sock, int order);
Packet makePacket(char* dataArr, Step currStep, int fileNum, int order);

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
  
    // GRADEME(argc, argv);

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
    ifstream *t;
    stringstream *sBuffer;
    char hashVal[20];
    string globalReadMessageString;
    ///
    // FILE* f;
    char tmpFileOpenConfirmMsg[sizeof(struct Packet)];
    char tmpServerMsg[sizeof(struct Packet)];
    char tmpserverConfirmation[sizeof(struct Packet)];
    char tmpENDServerConfirmation[sizeof(struct Packet)];

    ///
    
    fileCheckResults.open("fileCheckResults.txt");
    //
    //
    //        Send / receive / print 
    //
    try {

        // Create the socket
        c150debug->printf(C150APPLICATION,"Creating C150DgmSocket");
        C150DgmSocket *sock = new C150NastyDgmSocket(networkNastiness);
        C150NastyFile *F = new C150NastyFile(fileNastiness);
        // Tell the DGMSocket which server to talk to
        sock -> setServerName((char*)serverName.c_str());  
        sock->turnOnTimeouts(3000);

        /// assume file copying is done here 
        /*
        1. get a file and hash it. 
        */
        checkDirectory((char*)srcdir.c_str());
        SOURCE = opendir(srcdir.c_str());
       if (SOURCE == NULL) {
            fprintf(stderr,"Error opening target directory %s \n", srcdir.c_str());     
            exit(8);
        }

    
        string path;
        int currFileNum = 0;
        while ((sourceFile = readdir(SOURCE)) != NULL) {
           
            clientHashVal = "";
            // skip the . and .. names
            if ((strcmp(sourceFile->d_name, ".") == 0) || (strcmp(sourceFile->d_name, "..")  == 0 )) {
                 continue;  
            }
            currFileNum++;
            //  cout << "file #" << currFileNum <<" in directory" << endl;
            path = srcdir + "/" + sourceFile->d_name;
            // cout << "path: " << path << endl;
            // f = fopen((const char*)path.c_str(), "r");
            // cout << "test 1" << endl;
            t = new ifstream(path);
            sBuffer = new stringstream;
            *sBuffer << t->rdbuf();
            SHA1((const unsigned char *)sBuffer->str().c_str(), (sBuffer->str()).length(), obuf);
            cout << "\n current file being hashed: " << string(sourceFile->d_name) << endl;
            for (int i = 0; i < 20; i++)
            {
                sprintf(hashVal,"%02x",(unsigned int) obuf[i]);
                string stringHashVal(hashVal);
                clientHashVal += stringHashVal;
            }
            // get rid of this loop?
            bool isFileSendRetry = true;
            bool isEndToEndFailed = false;
            while (isFileSendRetry) {
                F->fopen((const char*)path.c_str(), "r");

                // 2.
                //send the file to the server, wait for its response of the hash code of the file that it just read.
                // perform a comparison between the hash code you currently have in this iteration and what is sent
                // back to you 
             
                string fileName = string(sourceFile->d_name);
                // const char* fakeFileSendArr = fakeFileSend.c_str();
                c150debug->printf(C150APPLICATION,"\n%s: Writing message: \"%s\"", argv[0], fileName.c_str());
                
                bool isFileOpenConfirmReceived = false;
                while (!isFileOpenConfirmReceived) {
                    sendPacket(string(sourceFile->d_name), SENDFILENAME, currFileNum, sock, -1);
                    sock->read(tmpFileOpenConfirmMsg, sizeof(struct Packet));
                    if(sock->timedout()) {
                        continue;
                    }
                    Packet *serverFileOpenPacket;
                    serverFileOpenPacket = (Packet*)tmpFileOpenConfirmMsg;
    
                    if(serverFileOpenPacket->currStep == CONFIRMFILENAME and serverFileOpenPacket->fileNum == currFileNum) {
                        isFileOpenConfirmReceived = true;
                    }

                    //TODO: if we get a hashcode from server, send status (this  is because server never got the status packet from befeore and we just jumped up here)
                    if(serverFileOpenPacket->currStep == HASHCODE and serverFileOpenPacket->fileNum == currFileNum and isEndToEndFailed) {
                        compareHashCodes(clientHashVal, (char*)globalReadMessageString.c_str(), sock, string(sourceFile->d_name), 1, sourceFile, currFileNum);
                    }
                }
                // after we get a confirmation of server opening the file:
                // send 5 packets
                 bool endOfFile = false;
                 string serverHashCode;
                //  char tmpBuf[1];
                char buffer[400];
                char tmpBuf[] = "\0";
                int counter = 0;
                //  int currPacketSize = 0;
                 
                while (!endOfFile) {
                        while((F->fread(tmpBuf, 1, 1) != 0 and counter <= 2000)) {
                            char prevChar = tmpBuf[0];
                            int numSameReads = 0;

                            while(numSameReads != 20) {
                                F->fseek(-1, SEEK_CUR);
                                F->fread(tmpBuf, 1, 1);
                                if(prevChar == tmpBuf[0]) {
                                    numSameReads++;
                                }
                                else {
                                    numSameReads = 0;
                                }
                                prevChar = tmpBuf[0];
                            }

                            buffer[counter % 400] = tmpBuf[0];
                            // cout << "added char to buffer:" << endl;
                            counter++;
                            // cout << "counter: " << counter << endl;
                            // send a packet every 400 bytes
                            if ((counter % 400) == 0) {
                                c150debug->printf(C150APPLICATION,"%s: sending SINGLE packets", argv[0]);
                                sendPacket(string(buffer), COPYFILE, currFileNum, sock, -1);
                                // cout << "sent packet" << endl;
                                // currPacketSize = 0;
                                // cout << "post sending packet" << endl;
                                if (counter == 2000) {
                                    counter = 0;
                                    // cout << "SENT FIVE PACKETS" << endl;
                                    c150debug->printf(C150APPLICATION,"%s: sending 5 packets", argv[0]);

                                    sendPacket("sent 5 packets", ALL5PACKETS, currFileNum, sock, -1);
                                    break;
                                }
                            }

                            // lastFPosition = F->ftell();
                        }

                    if(F->feof() != 0) {
                        endOfFile = true;
                        
                        c150debug->printf(C150APPLICATION,"%s: sending last end of file packet", argv[0]);
                        sendPacket(string(buffer), COPYFILE, currFileNum, sock, -1);
                        // send the end of file packet
                        // cout << "sent end of file packet" << endl;  
                        
                        c150debug->printf(C150APPLICATION,"%s: sending end of file", argv[0]);
                        // cout << "currPacketSize: " << currPacketSize << endl;
                        sendPacket(to_string(counter % 400), ENDOFFILE, currFileNum, sock, -1);
                    }
                    
                    bool receivedSend5Packets = false;
                    // listen for the message to send 5 extra packets
                    while (!receivedSend5Packets) {
                        // listen for a SENDPACKETS message
                        sock->read(tmpServerMsg, sizeof(struct Packet));
                         if (sock -> timedout()) {
                            if (endOfFile) {
                                sendPacket(to_string(counter % 400), ENDOFFILE, currFileNum, sock, -1);

                            } 
                            else {
                                sendPacket("sent 5 packets", ALL5PACKETS, currFileNum, sock, -1);
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
                        if (serverFileOpenPacket->currStep == SEND5PACKETS and serverFileOpenPacket->fileNum == currFileNum) {
                            if (string(serverFileOpenPacket->data) != "Send NEXT 5") {
                                 F->fseek(-2000, SEEK_CUR);
                                //  fseek(f, -2000, SEEK_CUR);
                            }
                            receivedSend5Packets = true;
                        }
                        if(endOfFile and serverFileOpenPacket->currStep == HASHCODE and serverFileOpenPacket->fileNum == currFileNum) {
                            // cout << "hash code received from server" << endl;
                            receivedSend5Packets = true;
                            // cout << "about to compare" << endl;
                            if (!compareHashCodes(clientHashVal, (char*)readMessageString.c_str(), sock, string(sourceFile->d_name), 1, sourceFile, currFileNum)) {
                                isEndToEndFailed = true;
                                // cout << "was wrong" << endl;
                            } else {
                                isFileSendRetry = false;
                            }
                        }
                    }
                }
                
                
                // if it is not the same, you need to resend the file and repeat this process of #2
                c150debug->printf(C150APPLICATION,"%s: reading server confirmation:", argv[0]);
                // read hash code from server
                int numRetries = 0;
                
                    while(!isEndToEndFailed) {
                        // cout << "waiting for confirmation" << endl;
                        readlen = sock -> read(tmpserverConfirmation, sizeof(struct Packet));

                        if(sock -> timedout()) {
                            if (numRetries == 5) {
                                throw C150NetworkException("the network is down");
                            }
                            numRetries++;
                            cout << "sock timedout. retrying" << endl;
                            // resend the hash code status
                            compareHashCodes(clientHashVal, (char*)serverHashCode.c_str(), sock, string(sourceFile->d_name), 1, sourceFile, currFileNum);
                            continue;
                        }
                       
                       
                        Packet *serverConfirmationPacket = (Packet*)tmpserverConfirmation;
                        char* serverConfirmation = serverConfirmationPacket->data;
                        serverConfirmation[strlen(serverConfirmation)] = '\0';
                        string serverConfirmationString(serverConfirmation);
                        cleanString(serverConfirmationString);
                        // if it does not time out
                        cout << "serverConfirmationPacket->fileNum: " << serverConfirmationPacket->fileNum << endl;
                        cout << "currFileNum: " << currFileNum << endl;
                        if (serverConfirmationPacket->currStep != CONFIRMATION or serverConfirmationPacket->fileNum != currFileNum) {
                                continue;
                        }
                        if (readlen != 0) {
                            break;
                        }
                    }
                F->fclose();
            }
            // fclose(f);
            delete t;
            delete sBuffer;   
        }
       // ending packet send here
        string sampleMsg = "ENDOFDIR";
        sendPacket(sampleMsg, ENDOFDIR, 0, sock, -1);
        bool isResetConfirmed = false;
        while(!isResetConfirmed) {
            readlen = sock -> read(tmpENDServerConfirmation, sizeof(struct Packet));
            if(sock -> timedout()) {
                sendPacket(sampleMsg, ENDOFDIR, 0, sock, -1);
                continue;
            }
            else {
                Packet *serverENDConfirmationPacket = (Packet*)tmpENDServerConfirmation;
                // if it does not time out
                if (serverENDConfirmationPacket->currStep != RESET) {
                        continue;
                }
                isResetConfirmed = true;
            }

        }
        closedir(SOURCE);
        fileCheckResults.close();
      

        // Check and print the incoming message
    }
    //
    //  Handle networking errors -- for now, just print message and give up!
    //
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
//                     checkAndPrintMessage
//
//        Make sure length is OK, clean up response buffer
//        and print it to standard output.
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
 // TODO: implement the proper num retry
bool compareHashCodes(string clientHashCode, char* serverHashCode, C150DgmSocket* sock, string currFile, int numRetry, dirent *sourceFile, int currFileNum) {
    if(string(serverHashCode) == clientHashCode) {
        // cout << string(serverHashCode) << " == " << clientHashCode << endl;
        fileCheckResults << "==" << endl;
        cout << "==" << endl;
        // 3. send confirmation message to server. 
        // *GRADING << "File: " << currFile << " end-to-end check succeeded, attempt " << numRetry << endl;
        c150debug->printf(C150APPLICATION,"%s: Writing message: \"%s\"", "fileclient", SUCCESS.c_str());
        string statusMessage = SUCCESS;
        sendPacket(SUCCESS, SENDSTATUS, currFileNum, sock, -1);
        return true;
    }
    else {
        // cout << string(serverHashCode) << " != " << clientHashCode << endl;
        // cout << "!=" << endl;
        // fileCheckResults << "!=" << endl;
        // *GRADING << "File: " << currFile << " end-to-end check failed, attempt " << numRetry << endl;
        c150debug->printf(C150APPLICATION,"%s: Writing message: \"%s\"", "fileclient", FAILURE.c_str());
        sendPacket(FAILURE, SENDSTATUS, currFileNum, sock, -1);
        return false;
    }
     
}

void sendPacket(string data, Step currStep, int fileNum, C150DgmSocket* sock, int order) {
        Packet newPacket = makePacket((char*)data.c_str(), currStep, fileNum, order);
        char * newPacketArr = (char *)&newPacket;
        sock -> write(newPacketArr, sizeof(newPacket)); 
        // cout << "finished writing to socket" << endl;
}

void
checkAndPrintMessage(ssize_t readlen, char *msg, ssize_t bufferlen) {
    // 
    // Except in case of timeouts, we're not expecting
    // a zero length read
    //
    if (readlen == 0) {
        throw C150NetworkException("Unexpected zero length read in client");
    }

    // DEFENSIVE PROGRAMMING: we aren't even trying to read this much
    // We're just being extra careful to check this
    if (readlen > (int)(bufferlen)) {
        throw C150NetworkException("Unexpected over length read in client");
    }

    //
    // Make sure server followed the rules and
    // sent a null-terminated string (well, we could
    // check that it's all legal characters, but 
    // at least we look for the null)
    //
    if(msg[readlen-1] != '\0') {
        throw C150NetworkException("Client received message that was not null terminated");     
    };

    //
    // Use a routine provided in c150utility.cpp to change any control
    // or non-printing characters to "." (this is just defensive programming:
    // if the server maliciously or inadvertently sent us junk characters, then we 
    // won't send them to our terminal -- some 
    // control characters can do nasty things!)
    //
    // Note: cleanString wants a C++ string, not a char*, so we make a temporary one
    // here. Not super-fast, but this is just a demo program.
    string s(msg);
    cleanString(s);

    // Echo the response on the console

    c150debug->printf(C150APPLICATION,"PRINTING RESPONSE: Response received is \"%s\"\n", s.c_str());
    printf("Response received is \"%s\"\n", s.c_str());

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
//        NEEDSWORK: should be factored into shared code w/pingserver
//        NEEDSWORK: document arguments
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
 
void setUpDebugLogging(const char *logname, int argc, char *argv[]) {

    //   
    //           Choose where debug output should go
    //
    // The default is that debug output goes to cerr.
    //
    // Uncomment the following three lines to direct
    // debug output to a file. Comment them
    // to default to the console.
    //
    // Note: the new DebugStream and ofstream MUST live after we return
    // from setUpDebugLogging, so we have to allocate
    // them dynamically.
    //
    //
    // Explanation: 
    // 
    //     The first line is ordinary C++ to open a file
    //     as an output stream.
    //
    //     The second line wraps that will all the services
    //     of a comp 150-IDS debug stream, and names that filestreamp.
    //
    //     The third line replaces the global variable c150debug
    //     and sets it to point to the new debugstream. Since c150debug
    //     is what all the c150 debug routines use to find the debug stream,
    //     you've now effectively overridden the default.
    //
    ofstream *outstreamp = new ofstream(logname);
    DebugStream *filestreamp = new DebugStream(outstreamp);
    DebugStream::setDefaultLogger(filestreamp);

    //
    //  Put the program name and a timestamp on each line of the debug log.
    //
    c150debug->setPrefix(argv[0]);
    c150debug->enableTimestamp(); 

    //
    // Ask to receive all classes of debug message
    //
    // See c150debug.h for other classes you can enable. To get more than
    // one class, you can or (|) the flags together and pass the combined
    // mask to c150debug -> enableLogging 
    //
    // By the way, the default is to disable all output except for
    // messages written with the C150ALWAYSLOG flag. Those are typically
    // used only for things like fatal errors. So, the default is
    // for the system to run quietly without producing debug output.
    //
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

Packet makePacket(char* dataArr, Step currStep, int fileNum, int order) {
    Packet newPacket;
    // newPacket.data = data;
    memcpy(newPacket.data, dataArr, strlen(dataArr) + 1);
    newPacket.currStep = currStep;
    newPacket.fileNum = fileNum;
    newPacket.order = order;
    return newPacket;
}
