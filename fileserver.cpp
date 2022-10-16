
#include "c150nastydgmsocket.h"
#include "c150debug.h"
#include <fstream>
#include <cstdlib> 
#include <dirent.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "c150grading.h"
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
    int fileNum;
    int order;
};
 string SUCCESS = "success";
 string FAILURE = "failure";
void setUpDebugLogging(const char *logname, int argc, char *argv[]);
void checkDirectory(char *dirname);
void createHashCode(string currFileName, string path, C150DgmSocket *sock, string targetDirectory, int currFileNum);
void sendPacket(string data, Step currStep, int fileNum, C150DgmSocket* sock, int order);
Packet makePacket(char* dataArr, Step currStep, int fileNum, int order);
string readMessage(char* buffer, Packet p);

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
      // amount of data read from socket
    int networkNastiness;               // how aggressively do we drop packets, etc?
    int fileNastiness;
    string targetDirectory;
    DIR *TARGET;                // Unix descriptor for target
    // struct dirent *targetFile;  // Directory entry for source file
	string builtHashVal = "";

    
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
    (void)fileNastiness;
    targetDirectory = argv[3];
    setUpDebugLogging("pingserverdebug.txt",argc, argv);
    c150debug->setIndent("    ");              // if we merge client and server
    ssize_t readlen;             // amount of data read from socket
    try{
        checkDirectory((char*)targetDirectory.c_str());
        TARGET = opendir(argv[3]);

        if (TARGET == NULL) {
            fprintf(stderr,"Error opening target directory %s \n", argv[3]);     
            exit(8);
        }

        //
        //  Loop copying the files
        //
        //    copyfile takes name of target file
        //
            string path;
        // int testCounter = 0;
            c150debug->printf(C150APPLICATION,"Creating C150NastyDgmSocket(nastiness=%d)",  networkNastiness);
            C150DgmSocket *sock = new C150NastyDgmSocket(networkNastiness);
            // targetFile = readdir(TARGET);
            //2.
            // before each file hashing, the server needs to be constantly listening for anything.
            // The server should hash the file it just received if the message is a file
            // Or, the server should send back a confirmation of receiving a status message if 
            // it receives a status update (SUCCESS OR FAILURE
             // skip the . and .. names
            int currFileNum = 0;
            while(1) {
            currFileNum++;
            cout << "currFileNum: " << currFileNum << endl;
            bool isFileRecieved = false;
            bool isStatusReceived = false;
            string fileString;

            while(!isFileRecieved) {
                
                char tmpfileMessagePacket[sizeof(struct Packet)];
                readlen = sock -> read(tmpfileMessagePacket, sizeof(struct Packet));
                if (readlen == 0) {
                    c150debug->printf(C150APPLICATION,"Read zero length message, trying again");
                    continue;
                }

                Packet *fileMessagePacket = (Packet*)tmpfileMessagePacket;
                char* fileMessage = fileMessagePacket->data;
                fileMessage[strlen(fileMessage)] = '\0';
                fileString = string(fileMessage);
                cleanString(fileString);
                // cout << "fileString: " << fileString << endl;
                //                                     // easier to work with, and cleanString
                /*
                plan for how to resolve packets dropping the " a file has just been received message":
                make sure that the incoming message being read is not a success or failure message.
                If it is, then tell the client to resend the file
                */
                // maybe cant set this to true in the event that we need to do a repeat hash?
                         // c150ids-supplied utility: changes
                //                                     // non-printing characters to .
                // cout << "fileMessagePacket->currStep: " << fileMessagePacket->currStep << endl;
                if (fileMessagePacket->currStep  == ENDOFDIR) {
                    string sampleMsg = "RESET";
                    Packet serverResetPacket = makePacket((char*)sampleMsg.c_str(), RESET, 0, -1);
                    char * serverResetPacketArr = (char *)&serverResetPacket;
                    currFileNum = 1;
                    cout << "reset received" << endl;
                    sock -> write(serverResetPacketArr, sizeof(serverResetPacket)); 
                    continue;
                }
                cout << "currFileNum: " << currFileNum << endl;
                cout << "fileMessagePacket->fileNum: " << fileMessagePacket->fileNum << endl;
                if (fileMessagePacket->currStep == SENDSTATUS and fileMessagePacket->fileNum == currFileNum - 1) {
                    //send packet with success/failure to client as confirmation
                    cout << "re-sending the confirmation packet by the server" << endl;
                    sendPacket("re-sending the confirmation packet", CONFIRMATION, currFileNum - 1, sock, -1);
                    continue;
                }

                if (fileMessagePacket->currStep != SENDFILE or fileMessagePacket->fileNum != currFileNum) {
                    continue;
                }
              
                isFileRecieved = true;
                cout << "message received from client" << endl;
                // for week 1, just compare "fileString", which is actually a hash code, 
                // with itself which may or may not be wrong 
            }
                 
                 createHashCode(fileString, path, sock, targetDirectory, currFileNum);
                //wait for status response from client
                while(!isStatusReceived) {
                    // if you get "a file has been received from the server" message, go back to the top
                    // of this loop 
                    char tmpStatusPacket[sizeof(struct Packet)];
                    readlen = sock -> read(tmpStatusPacket, sizeof(struct Packet));
                    if (readlen == 0) {
                        c150debug->printf(C150APPLICATION,"Read zero length message, trying again");
                        continue;
                    }
                     Packet *statusPacket = (Packet*)tmpStatusPacket;
                    char* statusMessage = statusPacket->data;
                    statusMessage[strlen(statusMessage)] = '\0';
                    string statusString(statusMessage);
                    cleanString(statusString);
                    if (statusString == (SUCCESS + " final") or statusString == (FAILURE + " final")) {
                        currFileNum = 0;
                    }

                    if(statusPacket->currStep != SENDSTATUS) {
                        createHashCode(fileString, path, sock, targetDirectory, currFileNum);
                    }
                   else {
                         isStatusReceived = true;
                        //  if(statusString == "success") {
                        //      *GRADING << "File: " << fileString << " end-to-end check succeeded" << endl;
                        //  }
                        //  else {
                        //      *GRADING << "File: " << fileString << " end-to-end check failed" << endl;
                        //  }
                        // send confirmation of receiving status to client 
                        string serverConfirmationMsg = "server confirmed " + statusString;
                        c150debug->printf(C150APPLICATION,"sending confirmation msg \" %s\"\n", serverConfirmationMsg.c_str());
                         Packet serverConfirmationPacket = makePacket((char*)serverConfirmationMsg.c_str(), CONFIRMATION, 0, -1);
                         char * serverConfirmationPacketArr = (char *)&serverConfirmationPacket;
                        sock -> write(serverConfirmationPacketArr, sizeof(serverConfirmationPacket)); 
                   }
                 }
            }
        closedir(TARGET);
    } 
    catch (C150NetworkException& e) {
        // Write to debug log
        c150debug->printf(C150ALWAYSLOG,"Caught C150NetworkException: %s\n",
                          e.formattedExplanation().c_str());
        // In case we're logging to a file, write to the console too
        cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation()\
                        << endl;
    }
    return 4;

    //////////////////////////////////////////////////////////////////////////////////////////////
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

void createHashCode(string currFileName, string path, C150DgmSocket *sock, string targetDirectory, int currFileNum) {
    char hashVal[20];
    unsigned char obuf[20];
    ifstream *t;
    stringstream *buffer;
    string builtHashVal = "";
    path = targetDirectory + "/" + currFileName;
    t = new ifstream(path);
    buffer = new stringstream;
    *buffer << t->rdbuf();
    SHA1((const unsigned char *)buffer->str().c_str(), (buffer->str()).length(), obuf);
    cout << "currFileName: " << currFileName << endl;
    cout << "current file being hashed on server-side: " << currFileName << endl;
    for (int i = 0; i < 20; i++)
    {
        sprintf(hashVal,"%02x",(unsigned int) obuf[i]);
        string stringHashVal(hashVal);
        builtHashVal += stringHashVal;
    }
        char* builtHashValArr = (char*)builtHashVal.c_str();

    c150debug->printf(C150APPLICATION,"Responding with message=\"%s\"", builtHashValArr);
    //send builtHashVal
    Packet hashCodePacket = makePacket(builtHashValArr,HASHCODE, currFileNum, -1);
     char * hashCodePacketArr = (char *)&hashCodePacket;
    sock -> write(hashCodePacketArr, sizeof(hashCodePacket));
    delete t;
    delete buffer;
}
//////////////////////////////////////////////////////////////////
     
    //  Set up debug message logging
    //


    //
    // We set a debug output indent in the server only, not the client.
    // That way, if we run both programs and merge the logs this way:
    //
    //    cat pingserverdebug.txt pingserverclient.txt | sort
    //
    // it will be easy to tell the server and client entries apart.
    //
    // Note that the above trick works because at the start of each
    // log entry is a timestamp that sort will indeed arrange in 
    // timestamp order, thus merging the logs by time across 
    // server and client.
    //
 
    // logs, server stuff will be indented

    //
    // Create socket, loop receiving and responding
    //
    





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
//        NEEDSWORK: should be factored and shared w/pingclient
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
    // debug output to a file. Comment them to 
    // default to the console
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

Packet makePacket(char* dataArr, Step currStep, int fileNum, int order) {
    Packet newPacket;
    // newPacket.data = data;
    memcpy(newPacket.data, dataArr, strlen(dataArr) + 1);
    newPacket.currStep = currStep;
    newPacket.fileNum = fileNum;
    newPacket.order = order;
    return newPacket;
}

void sendPacket(string data, Step currStep, int fileNum, C150DgmSocket* sock, int order) {
        Packet newPacket = makePacket((char*)data.c_str(), currStep, fileNum, order);
        char * newPacketArr = (char *)&newPacket;
        sock -> write(newPacketArr, sizeof(newPacket)); 
}


string readMessage(char* buffer, Packet* p, C150DgmSocket* sock) {
    sock -> read(buffer, sizeof(struct Packet));
    p = (Packet*)buffer;
    char* readMessage = p->data;
    readMessage[strlen(readMessage)] = '\0';
    string readMessageString(readMessage);
    cleanString(readMessageString);
    return readMessageString;
}




