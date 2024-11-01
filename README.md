# p4-AppClassification

## 0. Create environment for feature extracting
- Install conda
- Create conda environment
```bash
conda env create -f environment.yml
```
## 1. Dataset Preparation 
Download the **Application-Based Network Traffic Dataset** from [Kaggle](https://www.kaggle.com/datasets/applicationdataset/applicationbasednetworktrafficdataset) and place the dataset into the `dataset` folder.

## 2. Dataset Preprocessing
- The original `.pcap` files only contain raw packets without the Layer 2 (MAC) headers. We need to add arbitrary Layer 2 headers with MAC addresses to these packets:
    ```bash
    python add_l2.py
    ```

- To encode the class names as numbers, generate a dictionary that maps each class name to a unique number:
    ```bash
    python gen_dict.py
    ```

## 3. Feature Extraction
Use the preprocessed dataset to generate three CSV files: 
- `statistics_pv.csv`: Contains packet-level features.
- `statistics_sv.csv`: Contains session-level features.
- `statistics_5tuple.csv`: Contains 5 tuple infomation.

Run the feature extraction script:
```bash
python feature_extractor.py
```

## 4. Spilt testing and training dataset
- Move the `statistics_pv.csv`, `statistic_ss.csv` and `statistics_5tuple.csv` into `spilt_dataset folder`.
- It will generate folder name `csv_with_aug` and `csv_without_aug` seperately. (where "aug" stands for data augmentation)
- It will also generate `test_5tuple.csv`, which includes the 5-tuple information for the sessions in the testing dataset.
```bash
python spilt_data_with_aug.py
python split_data_without_aug.py
```

## 5. Training
- Move `csv_with_aug` into `./model_with_aug/`
- Move `csv_without_aug` into `./model_without_aug/`
- Run the three file in order
    1. 1_GRU.ipynb
    2. 2_SAE.ipynb
    3. 3_GRU_SAE_hybird_model.ipynb

## 6. Translate .h5 to tf
- Move the final `.h5` model (in gru_sae_hybird) to `convert_h5` folder
```bash
python h5_convert_tf.py {your model name}
## e.g.
python h5_convert_tf.py gru_sae_hybird.h5
```

## 7. Copy model to p4 switch
- Copy the model folder generated from step 6. into `./p4/cpp/tf_cpp/weight`
- Copy the `standardscaler_mean.csv` and `standardscaler_std.csv` generated from step 5 into `./p4/cpp/tf_cpp/weight/parameter/{"gru" or "sae"}`.
    - You need to copy gru and sae seperately. 

## 8. Run feature extractor on tofino p4 switch
- Enter `p4/p4src` folder
- Compile `appClassification.p4`
    1. Compile
        ```bash
        # Set your SDE path first
        export SDE = "your bf-sde-x.x.x folder path"
        # Compile
        $SDE/install/bin/bf-p4c -b tofino -a tna --create-graphs --verbose 2 appClassification.p4 -o p4c-out --bf-rt-schema p4c-out/bfrt.json --p4runtime-force-std-extern --p4runtime-files p4c-out/p4info.txt
        ```
    2. Edit **p4_devices.p4_programs.p4_pipelines[0:1].pipe_scope** in `p4c-out/appClassification.config` as follows:
       ```plaintext
       p4_devices.p4_programs.p4_pipelines[0].pipe_scope: [0, 2] => [0, 1]
       p4_devices.p4_programs.p4_pipelines[1].pipe_scope: [1, 3] => [2, 3]
       ```
       Note: This step can be ignored based on the port setting if your loop-back port is connected with `pipe_scope` 1 or 3.
    3. Generate IPDK/stratum format binary file
       ```bash
       docker run --rm -v $PWD:$PWD -w $PWD accton/tdi_pipeline_builder --p4c_conf_file=./p4c-out/appClassification.conf --bf_pipeline_config_binary_file=./appClassification.pb.bin
       ```
    4. Pack the new binary file and p4info file together to generate IPDK/stratum preload pipeline config
       ```bash
       docker run --rm -v $PWD:$PWD -w $PWD accton/pipe_cfg_gen  --bin appClassification.pb.bin --p4info p4c-out/p4info.txt
       ```
    5. Put the generated `pipeline_cfg.pb.txt` into `/etc/stratum`, this required root privilege
    6. Restart IPDK service to load the pipeline
       ```
       sudo systemctl restart ipdk
       ```
- Run appClassification on tofino
- Environment
    - Connect Host with switch on 12/0
    - Two recirculated loop
        - Connect 8/0 with 10/0 (between pipeline1 and pipeline2)
        - Connect 17/0 with 18/0 (between pipeline1 and pipeline1)
- Open the following port
    1. 8/0  => port 316 (pipeline2 to pipeline1 input port)
    2. 10/0 => port 48 (pipeline1 to pipeline2 output port)
    3. 12/0 => port 32 (host to swtich pipeline1)
    4. 17/0 => port 4 (pipeline1 to pipeline1 output port)
    5. 18/0 => port 12 (pipeline1 to pipeline1 input port)
    6. 21/0 => port 36 (connect to any host as receiver)
    7. 33/0 => port 64 (pipeline1 to cpu)


## 9. Generate pipe for IPC and prepare the model to classify input sessions
- Enter `p4/cpp` folder
```bash
# Compile (generate tf_cp)
make tf_cpp

# Run
tf_cp {class_name}
# e.g.
tf_cp Amazon
```

## 10. Write the mirror and table setting into dataplane
- Enter `p4/cpp` folder
- Create a new docker environment
```bash
# Create a new environment
sudo docker run --network=host -v $(pwd):$(pwd) -w $(pwd) -it ubuntu:20.04

# In Container
apt update
apt install build-essential protobuf-compiler-grpc libgrpc++-dev

# Compile (generate p4rt_exe)
make p4rt_cpp

# Run
p4rt_exe localhost:9559
```

* Hint: You should run `tf_cp` and `p4rt_exe` in the same folder, or IPC wouldn`t success.

## 11. Generate testing pcap
- Move `test_5tuple.csv` which generated by step 4. to `dataset` folder
- Run `gen_testing_pcap.py` and you will get a `testing` folder which includes all testing pcap.
```bash
python gen_testing_pcap.py
```
## 12. TCPreplay the traffic and check the accuracy
- Run tcpreplay on host
```bash
sudo tcpreplay -i {interface} {pcap_name}
# e.g.
sudo tcpreplay -i enp3s0f0 -M ./testing/iTunes.pcap
```
