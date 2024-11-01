#include "hybridModel.hpp"

#include <sys/time.h>
#include <unistd.h>

#include <iostream>
#include <string>

using namespace std;

const char* ModelLoadFail::what() { return "Model load fail"; }

const char* GraphOperationFail::what() { return "Failed Graph Operation"; }


HybridModel::HybridModel() {
    this->session = NULL;
    this->status = NULL;
    this->session_opts = NULL;
    this->graph = NULL;
    this->run_opts = NULL;
}



void HybridModel::load(string modelDirPath) {
    const char* tags = "serve";
    int ntags = 1;

    this->graph = TF_NewGraph();
    this->status = TF_NewStatus();
    this->session_opts = TF_NewSessionOptions();
    this->run_opts = NULL;

    this->session =
        TF_LoadSessionFromSavedModel(session_opts, run_opts, modelDirPath.c_str(), &tags, ntags, graph, NULL, status);

    if (TF_GetCode(this->status) != TF_Code::TF_OK) throw ModelLoadFail();
}

void DeallocateTensor(void* data, std::size_t len, void* arg) { std::free(data); }

/*
 * return: class index (0~9)
 */
int HybridModel::predict(vector<float> gru1DInputVec, vector<float> saeInputVec) {
    // ----- config input/output profile -----
    // Input
    int numInputs = this->inputOperName.size();
    TF_Output* inputs = (TF_Output*)malloc(sizeof(TF_Output) * numInputs);
    // GRU input profile (Operation Name is according "save_model_cli" tool)
    TF_Output gru1DInput = {TF_GraphOperationByName(this->graph, this->inputOperName[input_type_t::GRU].c_str()), 0};
    if (!gru1DInput.oper) throw GraphOperationFail();
    inputs[0] = gru1DInput;
    // SAE input profile (Operation Name is according "save_model_cli" tool)
    TF_Output saeInput = {TF_GraphOperationByName(this->graph, this->inputOperName[input_type_t::SAE].c_str()), 0};
    if (!saeInput.oper) throw GraphOperationFail();
    inputs[1] = saeInput;
    
    // Output
    int numOutputs = this->outputOperName.size();
    TF_Output* outputs = (TF_Output*)malloc(sizeof(TF_Output) * numOutputs);
    TF_Output output = {TF_GraphOperationByName(this->graph, this->outputOperName[0].c_str()), 0};
    if (!output.oper) throw GraphOperationFail();
    outputs[0] = output;
    // ===== config input/output profile end =====


    // ----- set & allocate input/output value memory -----
    TF_Tensor** inputValues = (TF_Tensor**)malloc(sizeof(TF_Tensor*) * numInputs);
    TF_Tensor** outputValues = (TF_Tensor**)malloc(sizeof(TF_Tensor*) * numOutputs);

    // GRU input
    size_t gru1DInputSize = sizeof(float);
    for (auto i : this->gru1DDims) gru1DInputSize *= abs(i);
    auto gru1DData = static_cast<float*>(malloc(gru1DInputSize));
    std::copy(gru1DInputVec.begin(), gru1DInputVec.end(), gru1DData);
    TF_Tensor* gru1DTensor =
        TF_NewTensor(TF_DataType::TF_FLOAT, this->gru1DDims.data(), static_cast<int>(this->gru1DDims.size()), gru1DData,
                     gru1DInputSize, DeallocateTensor, nullptr);
    inputValues[0] = gru1DTensor;

    // SAE input
    size_t saeInputSize = sizeof(float);
    for (auto i : this->saeDims) saeInputSize *= abs(i);
    auto saeData = static_cast<float*>(malloc(saeInputSize));
    std::copy(saeInputVec.begin(), saeInputVec.end(), saeData);
    TF_Tensor* saeTensor =
        TF_NewTensor(TF_DataType::TF_FLOAT, this->saeDims.data(), static_cast<int>(this->saeDims.size()), saeData,
                     saeInputSize, DeallocateTensor, nullptr);
    inputValues[1] = saeTensor;
    // ===== set & allocate input/output value memory end =====


    // ----- Predict, return answer and release memory space -----
    TF_SessionRun(this->session, NULL, inputs, inputValues, numInputs, outputs, outputValues, numOutputs, NULL, 0, NULL,
                  this->status);
    float* result = static_cast<float*>(TF_TensorData(outputValues[0]));


    int max_location = 0;
    float max_value = 0.0;
    for (int i = 0; i < OUTPUT_NUM; i++) {
        if (result[i] > max_value) {
            max_value = result[i];
            max_location = i;
        }
    }

    free(inputs);
    free(outputs);
    free(inputValues);
    free(outputValues);
    free(gru1DTensor);
    free(saeTensor);

    return max_location;
    // ===== Predict, return answer and release memory space end =====
}



string HybridModel::getType(int trafficType) {
    switch (trafficType) {
        case 0:
            return "Amazon";
        case 1:
            return "CyberGhost";
        case 2:
            return "Deezer";
        case 3:
            return "Discord";
        case 4:
            return "Dropbox";
        case 5:
            return "Epic";
        case 6:
            return "Facebook";
        case 7:
            return "Hotspot";
        case 8:
            return "iTunes";
        case 9:
            return "Microsoft";
        case 10:
            return "ProtonVPN";
        case 11:
            return "Skype";
        case 12:
            return "Slack";
        case 13:
            return "SoulseekQt";
        case 14:
            return "Spotify";
        case 15:
            return "Steam";
        case 16:
            return "Telegram";
        case 17:
            return "TuneIn";
        case 18:
            return "TunnelBear";
        case 19:
            return "Ultrasurf";
        case 20:
            return "WhatsApp";
        case 21:
            return "Zoom";
    }
    // switch (trafficType) {
    //     case 0:
    //         return "aim_chat";
    //     case 1:
    //         return "email";
    //     case 2:
    //         return "facebook_audio";
    //     case 3:
    //         return "facebook_chat";
    //     case 4:
    //         return "facebook_video";
    //     case 5:
    //         return "ftps";
    //     case 6:
    //         return "gmail_chat";
    //     case 7:
    //         return "hangouts_audio";
    //     case 8:
    //         return "hangouts_chat";
    //     case 9:
    //         return "hangouts_video";
    //     case 10:
    //         return "icq_chat";
    //     case 11:
    //         return "netflix";
    //     case 12:
    //         return "scp";
    //     case 13:
    //         return "sftp";
    //     case 14:
    //         return "skype_audio";
    //     case 15:
    //         return "skype_chat";
    //     case 16:
    //         return "skype_file";
    //     case 17:
    //         return "skype_video";
    //     case 18:
    //         return "spotify";
    //     case 19:
    //         return "vimeo";
    //     case 20:
    //         return "voipbuster";
    //     case 21:
    //         return "youtube";
    //     case 22:
    //         return "vpn_aim_chat";
    //     case 23:
    //         return "vpn_bittorrent";
    //     case 24:
    //         return "vpn_email";
    //     case 25:
    //         return "vpn_facebook_audio";
    //     case 26:
    //         return "vpn_facebook_chat";
    //     case 27:
    //         return "vpn_ftps";
    //     case 28:
    //         return "vpn_hangouts_audio";
    //     case 29:
    //         return "vpn_hangouts_chat";
    //     case 30:
    //         return "vpn_icq_chat";
    //     case 31:
    //         return "vpn_netflix";
    //     case 32:
    //         return "vpn_sftp";
    //     case 33:
    //         return "vpn_skype_audio";
    //     case 34:
    //         return "vpn_skype_chat";
    //     case 35:
    //         return "vpn_skype_files";
    //     case 36:
    //         return "vpn_spotify";
    //     case 37:
    //         return "vpn_vimeo";
    //     case 38:
    //         return "vpn_voipbuster";
    //     case 39:
    //         return "vpn_youtube";
    // }
    return "";
}