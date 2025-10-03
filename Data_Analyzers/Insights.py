print("Initialization successful")

import pandas as pd
from sklearn.ensemble import IsolationForest

dataset = pd.read_csv(r"C:\Harshvardhan's_codes\XFlowAI\C++_sniffers\low.csv")

print(dataset.head())

print(dataset.describe())



