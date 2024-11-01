#include <iostream>
#include <vector>
#include <sys/time.h>
#include <unistd.h>
#include <tensorflow/c/c_api.h>
#include <exception>
#include <math.h>
#include "hybridModel.hpp"
#include "standardScaler.hpp"

using namespace std;

#define NUMBER_OF_RESULT 100
#define NUMBER_OS_SAMPLES 1000

int main() {
  // ------- initialize -------
  timeval start;
  timeval end;
  HybridModel model;
  StandardScaler saeScaler;
  StandardScaler cnn1dScaler;
  
  vector<float> cnn1DInput(12*25, 1.0);
  vector<float> saeInput(26, 1.0);
  
  cout << "start" << endl;
 
  cnn1dScaler.fit_transform("c++/parameter/cnn1d");
  saeScaler.fit_transform("c++/parameter/sae");
  model.load("/root/cia/redduck/iotIDS/c++_python_model/c++/model/cnn_sae_hybrid");

  cnn1DInput = cnn1dScaler.transform(cnn1DInput);
  saeInput = saeScaler.transform(saeInput);

  // ======= initialize end =======
  unsigned long totalUs = 0;
  int trafficType;
  int tmp;

  trafficType = model.predict(cnn1DInput, saeInput);

  for (int i = 0; i < NUMBER_OF_RESULT; i++) {
    gettimeofday(&start, NULL);
    for (int j = 0; j < NUMBER_OS_SAMPLES; j++) {    
      trafficType = model.predict(cnn1DInput, saeInput);

      // if(trafficType == HybridModel::malware_type_t::MITM) {
      //   int rfTrafficType = decision_tree_predict(decisionTreeInput);
      //   if (rfTrafficType == 0) 
      //     trafficType = HybridModel::malware_type_t::INJECTION;
      //   else if (rfTrafficType == 1)
      //     trafficType = HybridModel::malware_type_t::MITM;
      //   else if (rfTrafficType == 2)
      //     trafficType = HybridModel::malware_type_t::DDOS;
      // }
    }

    gettimeofday(&end, NULL);
    unsigned long diff;
    diff = 1000000 * (end.tv_sec-start.tv_sec)+ end.tv_usec-start.tv_usec;
    // cout << "ans: " << trafficType << endl;
    // cout << "sec: " << diff / pow(10, 6) << endl;
    totalUs += diff;
  }
  cout << "avg time (s): " << double((totalUs / NUMBER_OF_RESULT)) / pow(10, 6) << endl;

  return 0;
}