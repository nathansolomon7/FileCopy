
#include "c150nastydgmsocket.h"
#include "c150debug.h"
#include <fstream>
#include <cstdlib> 
#include <dirent.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
using namespace C150NETWORK;  // for all the comp150 utilities 


void setUpDebugLogging(const char *logname, int argc, char *argv[]);
void checkDirectory(char *dirname);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                           main program
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
 
int
main(int argc, char *argv[])
{

    //
    // Variable declarations
    //
      // amount of data read from socket
    int networkNastiness;               // how aggressively do we drop packets, etc?
    int fileNastiness;
    string targetDirectory;
    DIR *TARGET;                // Unix descriptor for target
    struct dirent *targetFile;  // Directory entry for source file
    char hashVal[20];
	string builtHashVal = "";
    ifstream *t;
    stringstream *buffer;
    unsigned char obuf[20];

   
    //
    // Check command line and parse arguments
    //
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
    char fileMessage[512];
    char statusMessage[512];
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
        while ((targetFile = readdir(TARGET)) != NULL) {
            //2.
            // before each file hashing, the server needs to be constantly listening for anything.
            // The server should hash the file it just received if the message is a file
            // Or, the server should send back a confirmation of receiving a status message if 
            // it receives a status update (SUCCESS OR FAILURE
             // skip the . and .. names
            if ((strcmp(targetFile->d_name, ".") == 0) ||
            (strcmp(targetFile->d_name, "..")  == 0 )) {
                  cout << "is a . or .. . Skipping this file" << endl;
                  continue;          // never copy . or ..
                //argv[j] needs to be a path
            }
            else {
                 cout << "targetFile->d_name: " << string(targetFile->d_name) << endl;
                //  cout << "contains a . or .. . Skipping this file" << endl;
            }

            bool isFileRecieved = false;
            bool isStatusReceived = false;
            while(!isFileRecieved) {
                readlen = sock -> read(fileMessage, sizeof(fileMessage)-1);
                if (readlen == 0) {
                    c150debug->printf(C150APPLICATION,"Read zero length message, trying again");
                    continue;
                }
                fileMessage[readlen] = '\0';  // make sure null terminated
                string fileString(fileMessage); // Convert to C++ string ...it's slightly
                                                    // easier to work with, and cleanString
                isFileRecieved = true;
                cleanString(fileString);            // c150ids-supplied utility: changes
                                                    // non-printing characters to .
                cout << "message received from client" << endl;
                // for week 1, just compare "fileString", which is actually a hash code, 
                // with itself which may or may not be wrong 
            }

                builtHashVal = "";
                path = targetDirectory + "/" + targetFile->d_name;
                t = new ifstream(path);
                buffer = new stringstream;
                *buffer << t->rdbuf();
                SHA1((const unsigned char *)buffer->str().c_str(), (buffer->str()).length(), obuf);
                cout << "current file being hashed on server-side: " << string(targetFile->d_name) << endl;
                for (int i = 0; i < 20; i++)
                {
                    sprintf(hashVal,"%02x",(unsigned int) obuf[i]);
                    string stringHashVal(hashVal);
                    builtHashVal += stringHashVal;
                }
                 const char* builtHashValArr = builtHashVal.c_str();

                c150debug->printf(C150APPLICATION,"Responding with message=\"%s\"", builtHashValArr);
                //send builtHashVal
                sock -> write(builtHashValArr, builtHashVal.length() + 1);
                //wait for status response from client
                while(!isStatusReceived) {
                    readlen = sock -> read(statusMessage, sizeof(statusMessage)-1);
                    if (readlen == 0) {
                        c150debug->printf(C150APPLICATION,"Read zero length message, trying again");
                        continue;
                    }

                    statusMessage[readlen] = '\0';  // make sure null terminated
                    string statusString(statusMessage); // Convert to C++ string ...it's slightly
                                                        // easier to work with, and cleanString
                    isStatusReceived = true;
                    cleanString(statusString);   
                    // send confirmation of receiving status to client 
                    sock -> write(statusString.c_str(), statusString.length() + 1);     

                 }

                delete t;
                delete buffer;
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

