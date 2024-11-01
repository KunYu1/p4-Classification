#include <arpa/inet.h>
#include <getopt.h>
#include <math.h>
#include <pcap.h>
#include <signal.h>
#include <sys/time.h>
#include <tensorflow/c/c_api.h>
#include <unistd.h>

#include <array>
#include <ctime>
#include <exception>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <vector>



#ifndef _IPC_H_
#define _IPC_H_
#include "../../ipc/IPC.hpp"
#endif


#include "hybridModel.hpp"
#include "standardScaler.hpp"


int fifo;
std::ofstream pvCsvFile;
std::ofstream ssCsvFile;

std::unordered_map<string, int> statisticMap;



void sigintHandler(int signum);

void initializeFeatureCsvs(std::ofstream& pvCsv, std::ofstream& ssCsv);
void writeVectorToCsv(const std::vector<float>& vector, std::ofstream& outfile);

void writeVectorToCsv(const std::unordered_map<string, int>& statisticMap, std::ofstream& outfile);


int main(int argc, char** argv) {
    signal(SIGINT, sigintHandler);

    string basePath = string(argv[1]);
    string pvPath = "./" + basePath + "/" + string(argv[2]);
    string ssPath = "./" + basePath + "/" + string(argv[3]);

    pvCsvFile.open(pvPath.c_str());
    ssCsvFile.open(ssPath.c_str());
    if(!pvCsvFile || !ssCsvFile) {
        return 0;
    }

    initializeFeatureCsvs(pvCsvFile, ssCsvFile);


    vector<float> cnn1DInput(8 * 20, 1.0);
    vector<float> saeInput(20, 1.0);


    std::cerr << "--------- start to listening FIFO ---------" << std::endl;

    IPC::setupIPC();

    fifo = IPC::readFromIPC();



    while (true) {
        int size1, size2;
        timeval fifoStartTime, fifoEndTime;
        if (read(fifo, &fifoStartTime, sizeof(fifoStartTime)) == 0) {
            continue;
        }
        if (read(fifo, &size1, sizeof(size1)) == 0) {
            continue;
        }
        if (read(fifo, &size2, sizeof(size1)) == 0) {
            continue;
        }

        std::cout << "size1 = " << size1 << std::endl;
        std::cout << "size2 = " << size2 << std::endl;

        //  Read features from fifo
        for (int i = 0; i < size1; i++) {
            float value;
            read(fifo, &value, sizeof(value));
            cnn1DInput[i] = value;
            // std::cout << value << std::endl;
        }
        std::cout << std::endl;
        for (int i = 0; i < size2; i++) {
            float value;
            read(fifo, &value, sizeof(value));
            saeInput[i] = value;
            // std::cout << value << std::endl;
        }

        writeVectorToCsv(cnn1DInput, pvCsvFile);
        writeVectorToCsv(saeInput, ssCsvFile);
    }
}

void initializeFeatureCsvs(std::ofstream& pvCsv, std::ofstream& ssCsv) {
    pvCsv
        << "1_fwd_pktMeanSize,1_bwd_pktMeanSize,1_fwd_pktTotalSize,1_bwd_pktTotalSize,1_fwd_pktVarSize,1_bwd_"
           "pktVarSize,1_fwd_pktMinSize,1_bwd_pktMinSize,1_fwd_pktMaxSize,1_bwd_pktMaxSize,"
           "1_fwd_ttlMeanSize,1_bwd_ttlMeanSize,1_fwd_ttlTotalSize,1_bwd_ttlTotalSize,1_fwd_ttlVarSize,1_bwd_"
           "ttlVarSize,1_fwd_ttlMinSize,1_bwd_ttlMinSize,1_fwd_ttlMaxSize,1_bwd_ttlMaxSize,2_fwd_pktMeanSize,2_bwd_"
           "pktMeanSize,2_fwd_pktTotalSize,2_bwd_pktTotalSize,2_fwd_pktVarSize,2_bwd_pktVarSize,2_fwd_pktMinSize,2_bwd_"
           "pktMinSize,2_fwd_pktMaxSize,2_bwd_pktMaxSize,2_fwd_ttlMeanSize,2_bwd_"
           "ttlMeanSize,2_fwd_ttlTotalSize,2_bwd_ttlTotalSize,2_fwd_ttlVarSize,2_bwd_ttlVarSize,2_fwd_ttlMinSize,2_bwd_"
           "ttlMinSize,2_fwd_ttlMaxSize,2_bwd_ttlMaxSize,3_fwd_pktMeanSize,3_bwd_pktMeanSize,3_fwd_pktTotalSize,3_bwd_"
           "pktTotalSize,3_fwd_pktVarSize,3_bwd_pktVarSize,3_fwd_pktMinSize,3_bwd_pktMinSize,3_fwd_pktMaxSize,3_bwd_"
           "pktMaxSize,3_fwd_ttlMeanSize,3_bwd_ttlMeanSize,3_fwd_ttlTotalSize,3_bwd_"
           "ttlTotalSize,3_fwd_ttlVarSize,3_bwd_ttlVarSize,3_fwd_ttlMinSize,3_bwd_ttlMinSize,3_fwd_ttlMaxSize,3_bwd_"
           "ttlMaxSize,4_fwd_pktMeanSize,4_bwd_pktMeanSize,4_fwd_pktTotalSize,4_bwd_pktTotalSize,4_fwd_pktVarSize,4_"
           "bwd_pktVarSize,4_fwd_pktMinSize,4_bwd_pktMinSize,4_fwd_pktMaxSize,4_bwd_pktMaxSize,4_fwd_ttlMeanSize,4_bwd_ttlMeanSize,4_fwd_ttlTotalSize,4_bwd_ttlTotalSize,4_fwd_ttlVarSize,4_"
           "bwd_ttlVarSize,4_fwd_ttlMinSize,4_bwd_ttlMinSize,4_fwd_ttlMaxSize,4_bwd_ttlMaxSize,5_fwd_pktMeanSize,5_bwd_"
           "pktMeanSize,5_fwd_pktTotalSize,5_bwd_pktTotalSize,5_fwd_pktVarSize,5_bwd_pktVarSize,5_fwd_pktMinSize,5_bwd_"
           "pktMinSize,5_fwd_pktMaxSize,5_bwd_pktMaxSize,5_fwd_ttlMeanSize,5_bwd_"
           "ttlMeanSize,5_fwd_ttlTotalSize,5_bwd_ttlTotalSize,5_fwd_ttlVarSize,5_bwd_ttlVarSize,5_fwd_ttlMinSize,5_bwd_"
           "ttlMinSize,5_fwd_ttlMaxSize,5_bwd_ttlMaxSize,6_fwd_pktMeanSize,6_bwd_pktMeanSize,6_fwd_pktTotalSize,6_bwd_"
           "pktTotalSize,6_fwd_pktVarSize,6_bwd_pktVarSize,6_fwd_pktMinSize,6_bwd_pktMinSize,6_fwd_pktMaxSize,6_bwd_"
           "pktMaxSize,6_fwd_ttlMeanSize,6_bwd_ttlMeanSize,6_fwd_ttlTotalSize,6_bwd_"
           "ttlTotalSize,6_fwd_ttlVarSize,6_bwd_ttlVarSize,6_fwd_ttlMinSize,6_bwd_ttlMinSize,6_fwd_ttlMaxSize,6_bwd_"
           "ttlMaxSize,7_fwd_pktMeanSize,7_bwd_pktMeanSize,7_fwd_pktTotalSize,7_bwd_pktTotalSize,7_fwd_pktVarSize,7_"
           "bwd_pktVarSize,7_fwd_pktMinSize,7_bwd_pktMinSize,7_fwd_pktMaxSize,7_bwd_pktMaxSize,7_fwd_ttlMeanSize,7_bwd_ttlMeanSize,7_fwd_ttlTotalSize,7_bwd_ttlTotalSize,7_fwd_ttlVarSize,7_"
           "bwd_ttlVarSize,7_fwd_ttlMinSize,7_bwd_ttlMinSize,7_fwd_ttlMaxSize,7_bwd_ttlMaxSize,8_fwd_pktMeanSize,8_bwd_"
           "pktMeanSize,8_fwd_pktTotalSize,8_bwd_pktTotalSize,8_fwd_pktVarSize,8_bwd_pktVarSize,8_fwd_pktMinSize,8_bwd_"
           "pktMinSize,8_fwd_pktMaxSize,8_bwd_pktMaxSize,8_fwd_ttlMeanSize,8_bwd_"
           "ttlMeanSize,8_fwd_ttlTotalSize,8_bwd_ttlTotalSize,8_fwd_ttlVarSize,8_bwd_ttlVarSize,8_fwd_ttlMinSize,8_bwd_"
           "ttlMinSize,8_fwd_ttlMaxSize,8_bwd_ttlMaxSize"
        << std::endl;

    ssCsv << "pktTotalSize,pktMeanSize,pktVarSize,pktMinSize"
             "sessionConnectionTime,serviceType,windowTotal,windowMean,windowVar,windowMin,windowMax,"
             "l4PayloadTotalSize,l4PayloadMeanSize,l4PayloadVarSize,l4PayloadMinSize,l4PayloadMaxSize,"
             "numberOfRstFlag,numberOfPshFlag,numberOfKeepAlive,numberOfSyncFlood"
          << std::endl;
}




void writeVectorToCsv(const std::vector<float>& vec, std::ofstream& outfile) {
    for (int i = 0; i < vec.size(); i++) {
        outfile << vec[i];
        if (i != vec.size() - 1) {
            outfile << ",";
        }
    }
    outfile << std::endl;
}


void writeVectorToCsv(const std::unordered_map<string, int>& statisticMap, std::ofstream& outfile) {
    outfile << "Type,Count" << endl;
    for (auto entry : statisticMap) {
        outfile << entry.first << "," << entry.second << endl;
    }
}



void sigintHandler(int signum) {
    close(fifo);

    pvCsvFile.close();
    ssCsvFile.close();

    IPC::closedIPC();
    exit(0);
}
