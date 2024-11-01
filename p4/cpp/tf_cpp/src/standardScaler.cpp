#include "standardScaler.hpp"
#include <iostream>
#include <fstream>
#include <exception>

using namespace std;


StandardScaler::StandardScaler()
{
    values.push_back(vector<float>());
    values.push_back(vector<float>());
}

void StandardScaler::fit_transform(string dirPath)
{
    vector<ifstream> files(2);
    for (int i = 0; i < files.size(); i++) {
        files[i].open(dirPath + "/" + fileName[i]);
        
        if (!files[i].is_open()) 
            throw string(dirPath + "/" + fileName[i] + "file not found.");                        

        float value;
        while (files[i] >> value)
            values[i].push_back(value);
        files[i].close();
    }

    if (values[MEAN].size() != values[STD].size()) 
        throw string("mean vector size != std vector size");
}

void StandardScaler::std()
{
    for (int i = 0; i < values[STD].size(); i++) 
        cout << values[STD][i] << endl;
}

void StandardScaler::mean()
{
    for (int i = 0; i < values[MEAN].size(); i++) 
        cout << values[MEAN][i] << endl;
}

vector<float> StandardScaler::transform(vector<float> oriValue) {
    if (oriValue.size() != values[MEAN].size())
        throw string("values vector size != mean/std vector size");
    
    vector<float> ret(oriValue);
    for (int i = 0; i < ret.size(); i++)
        ret[i] = (ret[i] - values[MEAN][i]) / values[STD][i];
    
    return ret;
}