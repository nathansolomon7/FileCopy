// --------------------------------------------------------------
//
//                        pingclient.cpp
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


#include "c150dgmsocket.h"
#include "c150debug.h"
#include <fstream>
#include <dirent.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "c150grading.h"
#include <unistd.h>
// using std::ofstream;
using namespace std;          // for C++ std library
using namespace C150NETWORK;  // for all the comp150 utilities 
typedef enum Step{
    SENDFILE = 0,
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
    int order;
};


// forward declarations
void checkAndPrintMessage(ssize_t readlen, char *buf, ssize_t bufferlen);
void setUpDebugLogging(const char *logname, int argc, char *argv[]);
void checkDirectory(char *dirname);
void compareHashCodes(string clientHashCode, char* serverHashCode, C150DgmSocket* sock, string fileName, int numRetry, dirent *sourceFile);
Packet makePacket(char* dataArr, Step currStep, int order);

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
//   ofstream fileCheckResults;
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
    // int networkNastiness = atoi(argv[2]);
    // int filenastiness = atoi(argv[3]);
    string srcdir = argv[4];
    struct dirent *sourceFile; 
    string clientHashVal = "";
    unsigned char obuf[20];
    ifstream *t;
    stringstream *buffer;
    char hashVal[20];
    
    // fileCheckResults.open("fileCopyResults.txt");
    //
    //
    //        Send / receive / print 
    //
    try {

        // Create the socket
        c150debug->printf(C150APPLICATION,"Creating C150DgmSocket");
        C150DgmSocket *sock = new C150DgmSocket();

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
        int fileNum = 0;
        while ((sourceFile = readdir(SOURCE)) != NULL) {
            clientHashVal = "";
            // skip the . and .. names
            if ((strcmp(sourceFile->d_name, ".") == 0) || (strcmp(sourceFile->d_name, "..")  == 0 )) {
                 continue;  
            }
            fileNum++;

            path = srcdir + "/" + sourceFile->d_name;
            t = new ifstream(path);
            buffer = new stringstream;
            *buffer << t->rdbuf();
            SHA1((const unsigned char *)buffer->str().c_str(), (buffer->str()).length(), obuf);
            cout << "current file being hashed: " << string(sourceFile->d_name) << endl;
            for (int i = 0; i < 20; i++)
            {
                sprintf(hashVal,"%02x",(unsigned int) obuf[i]);
                string stringHashVal(hashVal);
                clientHashVal += stringHashVal;
            }
            bool isFileSendRetry = true;
            while (isFileSendRetry) {

            
                // 2.
                //send the file to the server, wait for its response of the hash code of the file that it just read.
                // perform a comparison between the hash code you currently have in this iteration and what is sent
                // back to you 
             
                string fakeFileSend = string(sourceFile->d_name);
                // const char* fakeFileSendArr = fakeFileSend.c_str();
                c150debug->printf(C150APPLICATION,"%s: Writing message: \"%s\"", argv[0], fakeFileSend.c_str());
               
                Packet newPacket = makePacket(sourceFile->d_name, SENDFILE, fileNum);
                char * newPacketArr = (char *)&newPacket;
                sock -> write(newPacketArr, sizeof(newPacket)); // +1 includes the null
                
                // if it is not the same, you need to resend the file and repeat this process of #2
                c150debug->printf(C150APPLICATION,"%s: reading server response:", argv[0]);
                // read hash code from server
                bool isConfirmReceived = false;
                int retryCounterHashCode = 0;
                while(!isConfirmReceived) {
                    // if hash code from server does not arrive, then skip this iteration of the while loop
                    // TODO: make sure that the response received is  a hash code and not a confirmation message
                    // If this occurs, then resend the hash code?
                    char tmpserverHashCode[sizeof(struct Packet)];
                   
                    readlen = sock -> read(tmpserverHashCode, sizeof(struct Packet));
                    
                    Packet *serverHashCodePacket = (Packet*)tmpserverHashCode;
                    char* serverHashCode = serverHashCodePacket->data;
                    serverHashCode[strlen(serverHashCode)] = '\0';
                    string serverHashCodeString(serverHashCode);
                    cleanString(serverHashCodeString);
                    // cout << "serverHashCodeString: " << serverHashCodeString << endl;
                    if(readlen == 0 or sock -> timedout()) {
                        retryCounterHashCode ++;
                        if (retryCounterHashCode == 5) {
                            isConfirmReceived = true;
                        }
                        // go back to top of "while(!isConfirmReceived) while loop to try 5 reads until"
                        // doing a full file retry
                        continue;
                    }
                    // checking to make sure that the hash code received is actually a hash code
                    if (serverHashCodePacket->currStep != HASHCODE) {
                        isConfirmReceived = true;
                        continue;
                    }
                    // the server got the file and you received back a hash code, so do not retry sending 
                    // the file/initial message again
                    isFileSendRetry = false;
                    
                    // checkAndPrintMessage(serverHashCodeString.length() - 1, serverHashCode, sizeof(serverHashCode));
                    // if the server hash val is not a hash code, go back to the top and resend "a file has 
                    // been sent message"
                    
                    compareHashCodes(clientHashVal, serverHashCode, sock, string(sourceFile->d_name), 1, sourceFile);

                    // reads sent from server
                    int numRetries = 0;
                    while(1) {
                        char tmpserverConfirmation[sizeof(struct Packet)];
                        readlen = sock -> read(tmpserverConfirmation, sizeof(struct Packet));
                    
                        if(sock -> timedout()) {
                            numRetries++;
                            cout << "sock timedout. retrying" << endl;
                            // resend the hash code status
                            compareHashCodes(clientHashVal, serverHashCode, sock, string(sourceFile->d_name), 1, sourceFile);
                            continue;
                        }
                       
                       
                        Packet *serverConfirmationPacket = (Packet*)tmpserverConfirmation;
                        char* serverConfirmation = serverConfirmationPacket->data;
                        serverConfirmation[strlen(serverConfirmation)] = '\0';
                        string serverConfirmationString(serverConfirmation);
                        cleanString(serverConfirmationString);
                        // if it does not time out
                        if (serverConfirmationPacket->currStep != CONFIRMATION) {
                                continue;
                        }
                        if(readlen != 0) {
                            isConfirmReceived = true;
                            // checkAndPrintMessage(serverConfirmationString.length() -1 , serverConfirmation, sizeof(serverConfirmation));
                            // cout << "the client received the confirmation from the server" << endl;
                            break;
                        }
                        if(numRetries == 5) {
                            throw C150NetworkException("the network is down");
                        }
                    }
                //TESTING: assuming only one hash code gets sent back from the server
                // hash code from server is contained in incoming message
                }

            }
                delete t;
                delete buffer;
                
        }
        //TODO: insert ending packet send here
        string sampleMsg = "ENDOFDIR";
        Packet newPacket = makePacket((char*)sampleMsg.c_str(), ENDOFDIR, 0);
        char * newPacketArr = (char *)&newPacket;
        sock -> write(newPacketArr, sizeof(newPacket)); // +1 includes the null
        bool isResetConfirmed = false;
        while(!isResetConfirmed) {
            char tmpENDServerConfirmation[sizeof(struct Packet)];
            readlen = sock -> read(tmpENDServerConfirmation, sizeof(struct Packet));
            if(sock -> timedout()) {
                Packet newPacket = makePacket((char*)sampleMsg.c_str(), ENDOFDIR, 0);
                char * newPacketArr = (char *)&newPacket;
                sock -> write(newPacketArr, sizeof(newPacket)); // +1 includes the null
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
        // fileCheckResults.close();
      

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
void compareHashCodes(string clientHashCode, char* serverHashCode, C150DgmSocket* sock, string currFile, int numRetry, dirent *sourceFile) {
    if(string(serverHashCode) == clientHashCode) {
        cout << string(serverHashCode) << " == " << clientHashCode << endl;
        cout << "==" << endl;
        // 3. send confirmation message to server. 
        // *GRADING << "File: " << currFile << " end-to-end check succeeded, attempt " << numRetry << endl;
        c150debug->printf(C150APPLICATION,"%s: Writing message: \"%s\"", "fileclient", SUCCESS.c_str());
        string statusMessage;
        // int f = open("seek", currFile);
        // if(lseek(f, sourceFile->d_off, SEEK_END) == NULL) {
        //     statusMessage = SUCCESS + " final";
        // }
        // else {
        //     statusMessage = SUCCESS;
        // }
        Packet newPacket = makePacket((char*)statusMessage.c_str(), SENDSTATUS, 0);
        char * newPacketArr = (char *)&newPacket;
        sock -> write(newPacketArr, sizeof(newPacket)); // +1 includes the null
    }
    else {
        cout << string(serverHashCode) << " != " << clientHashCode << endl;
        cout << "!=" << endl;
        // *GRADING << "File: " << currFile << " end-to-end check failed, attempt " << numRetry << endl;
        c150debug->printf(C150APPLICATION,"%s: Writing message: \"%s\"", "fileclient", FAILURE.c_str());
        string statusMessage;
        if(sourceFile + sourceFile->d_off == NULL) {
            statusMessage = FAILURE + " final";
        }
        else {
            statusMessage = FAILURE;
        }
        Packet newPacket = makePacket((char*)statusMessage.c_str(), SENDSTATUS, 0);
        char * newPacketArr = (char *)&newPacket;
        sock -> write(newPacketArr, sizeof(newPacket)); 
    }
     
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

Packet makePacket(char* dataArr, Step currStep, int order) {
    Packet newPacket;
    // newPacket.data = data;
    memcpy(newPacket.data, dataArr, strlen(dataArr) + 1);
    newPacket.currStep = currStep;
    newPacket.order = order;
    return newPacket;
}
