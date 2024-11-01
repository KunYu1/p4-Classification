#ifndef _STANDARD_SCALER
#define _STANDARD_SCALER

#include <vector>
#include <string>

using namespace std;

class StandardScaler
{
private:
    enum parameter_file_t {
        MEAN = 0,
        STD = 1
    };
    const vector<string> fileName{"standardscaler_mean.csv", "standardscaler_std.csv"};
    vector<vector<float> > values;

public:
    StandardScaler();
    void fit_transform(string dirPath); 
    vector<float> transform(vector<float> values);
    void std();
    void mean();
};

#endif