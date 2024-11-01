import pandas as pd
import os
from sklearn.model_selection import train_test_split

csv_pv = pd.read_csv('statistics_pv.csv')
csv_ss = pd.read_csv('statistics_ss.csv')
csv_5tuple = pd.read_csv('statistics_5tuple.csv')

X_pv = csv_pv.drop(columns=['LABEL'])  # csv_pv features
y_pv = csv_pv['LABEL']  # csv_pv labels
X_ss = csv_ss.drop(columns=['LABEL'])  # csv_ss features

X_pv_train, X_pv_test, y_pv_train, y_pv_test = train_test_split(
    X_pv, y_pv, test_size=0.2, random_state=42, stratify=y_pv
)

# Get the index from pv dataset
train_index = X_pv_train.index
test_index = X_pv_test.index

# Using the above index to spilt ss dataset
X_ss_train = X_ss.loc[train_index]
X_ss_test = X_ss.loc[test_index]

test_5tuple = csv_5tuple.loc[test_index]


# Save the file
gru_folder = 'csv_without_aug/gru_8_pkts_28_features_without_aug'
sae_folder = 'csv_without_aug/sae_8_pkts_14_features_without_aug'

os.makedirs(gru_folder, exist_ok=True)
os.makedirs(sae_folder, exist_ok=True)

X_pv_train.to_csv(f'{gru_folder}/x_train.csv', index=False)
y_pv_train.to_csv(f'{gru_folder}/y_train.csv', index=False)
X_pv_test.to_csv(f'{gru_folder}/x_test.csv', index=False)
y_pv_test.to_csv(f'{gru_folder}/y_test.csv', index=False)

X_ss_train.to_csv(f'{sae_folder}/x_train.csv', index=False)
y_pv_train.to_csv(f'{sae_folder}/y_train.csv', index=False)
X_ss_test.to_csv(f'{sae_folder}/x_test.csv', index=False)
y_pv_test.to_csv(f'{sae_folder}/y_test.csv', index=False)

test_5tuple.to_csv('test_5tuple.csv', index=False)


print("The data has been saved as separate CSV files.")
