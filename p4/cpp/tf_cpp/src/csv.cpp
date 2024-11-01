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
#include <sstream>
#include <unordered_map>
#include <vector>

#include "hybridModel.hpp"
#include "standardScaler.hpp"

using namespace std;

int main(int argc, char** argv) {
    std::cout << "--------- Run Tensorflow configuration ---------" << std::endl;

    HybridModel model;
    StandardScaler saeScaler;
    StandardScaler cnn1dScaler;

    vector<float> cnn1DInput(8 * 30, 1.0);
    vector<float> saeInput(25, 1.0);


    cnn1dScaler.fit_transform("/root/cia/samuel/p4-AppClassification/p4/cpp/weights/parameter/gru");
    saeScaler.fit_transform("/root/cia/samuel/p4-AppClassification/p4/cpp/weights/parameter/sae");
    model.load("/root/cia/samuel/p4-AppClassification/p4/cpp/weights/gru_sae_hybrid");


    // Initialize model to prevent cold start
    model.predict(cnn1DInput, saeInput);


    std::cout << "========= Tensorflow configuration end =========" << std::endl;

    std::ifstream pvCsvFile(argv[1]);
    std::ifstream ssCsvFile(argv[2]);

    string rawStr;
    getline(pvCsvFile, rawStr);
    getline(ssCsvFile, rawStr);

    for (int i = 0; i < cnn1DInput.size(); i++) {
        getline(pvCsvFile, rawStr, ',');
        istringstream iss;
        iss.str(rawStr);
        float value;
        iss >> value;
        cnn1DInput[i] = value;
    }


    for (int i = 0; i < saeInput.size(); i++) {
        getline(ssCsvFile, rawStr, ',');
        istringstream iss;
        iss.str(rawStr);
        float value;
        iss >> value;
        saeInput[i] = value;
    }


    cnn1DInput = cnn1dScaler.transform(cnn1DInput);
    saeInput = saeScaler.transform(saeInput);

    cout << "TV" << endl;
    for (auto value : cnn1DInput) {
        cout << value << " ";
    }
    cout << endl;

    cout << "SS" << endl;
    for (auto value : saeInput) {
        cout << value << " ";
    }
    cout << endl;


    clock_t startTime, endTime;
    startTime = clock();
    int trafficType = model.predict(cnn1DInput, saeInput);
    endTime = clock();


    std::cout << "trafficType = " << trafficType << " " << HybridModel::getType(trafficType) << std::endl;
    std::cout << "Classification Time = " << double(endTime - startTime) / CLOCKS_PER_SEC << " s" << std::endl;
    std::cout << std::endl;
}