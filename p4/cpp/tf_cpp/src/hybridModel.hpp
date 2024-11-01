#ifndef _HYBRIDMODEL
#define _HYBRIDMODEL

#include <tensorflow/c/c_api_experimental.h>

#include <array>
#include <exception>
#include <string>
#include <vector>


using namespace std;

class ModelLoadFail : public exception {
   public:
    const char *what();
};

class GraphOperationFail : public exception {
   public:
    const char *what();
};

class HybridModel {
   private:
    enum input_type_t { GRU = 0, SAE = 1 };
    TF_Session *session;
    TF_Status *status;
    TF_SessionOptions *session_opts;
    TF_Graph *graph;
    TF_Buffer *run_opts;

    const int OUTPUT_NUM = 22;


    const vector<string> inputOperName{"serving_default_input_1",
                                       "serving_default_sae_input"};  // index according input_type_t
    const vector<string> outputOperName{"StatefulPartitionedCall"};
    const array<int64_t, 3> gru1DDims{1, 8, 18};
    const array<int64_t, 2> saeDims{1, 13};
    const array<int64_t, 2> outputDims{1, 22};
    // const array<float, 3> gru1DDims{1, 8, 30};
    // const array<float, 2> saeDims{1, 25};
    // const array<float, 2> outputDims{1, 40};
    void allocate_input_array();

   public:
    // enum malware_type_t {
    //     aim_chat = 0,
    //     email = 1,
    //     facebook_audio = 2,
    //     facebook_chat = 3,
    //     facebook_video = 4,
    //     ftps = 5,
    //     gmail_chat = 6,
    //     hangouts_audio = 7,
    //     hangouts_chat = 8,
    //     hangouts_video = 9,
    //     icq_chat = 10,
    //     netflix = 11,
    //     scp = 12,
    //     sftp = 13,
    //     skype_audio = 14,
    //     skype_chat = 15,
    //     skype_file = 16,
    //     skype_video = 17,
    //     spotify = 18,
    //     vimeo = 19,
    //     voipbuster = 20,
    //     youtube = 21,
    //     vpn_aim_chat = 22,
    //     vpn_bittorrent = 23,
    //     vpn_email = 24,
    //     vpn_facebook_audio = 25,
    //     vpn_facebook_chat = 26,
    //     vpn_ftps = 27,
    //     vpn_hangouts_audio = 28,
    //     vpn_hangouts_chat = 29,
    //     vpn_icq_chat = 30,
    //     vpn_netflix = 31,
    //     vpn_sftp = 32,
    //     vpn_skype_audio = 33,
    //     vpn_skype_chat = 34,
    //     vpn_skype_files = 35,
    //     vpn_spotify = 36,
    //     vpn_vimeo = 37,
    //     vpn_voipbuster = 38,
    //     vpn_youtube = 39
    // };
    enum malware_type_t {
        Amazon = 0,
        CyberGhost = 1,
        Deezer = 2,
        Discord = 3,
        Dropbox = 4,
        Epic = 5,
        Facebook = 6,
        Hotspot = 7,
        iTunes = 8,
        Microsoft = 9,
        ProtonVPN = 10,
        Skype = 11,
        Slack = 12,
        SoulseekQt = 13,
        Spotify = 14,
        Steam = 15,
        Telegram = 16,
        TuneIn = 17,
        TunnelBear = 18,
        Ultrasurf = 19,
        WhatsApp = 20,
        Zoom = 21
    };
    HybridModel();
    void load(string modelDirPath);
    int predict(vector<float> gru1DInput, vector<float> saeInput);
    static string getType(int trafficType);
};

#endif