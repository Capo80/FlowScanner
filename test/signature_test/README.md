# FlowScanner signature generator


This folder is used to generate and test signature generation for the FlowScanner project.

Signature generation works as follows:
- We start with 2 trace files, one from a dataset of malware, one from a dataset of goodware, this are kept in the "traces" folder but, due to size, will be moved outside the repo
- With "flow_sign_gen.py", we run trough the malware traces, split into train and test, and record each zone observed as a signature of that specific malware, the we parse the goodware traces and remove all signatures found in goodware, this will generate a "flow_sign*.py" file in the signatures folder;
- With "flow_sign_test.py", we then take the train set signature and run then trough the test set to check the detection rate, this a ".json" file in the "test_outputs" folder;
- Finally, we can extract the information generated using the "compare_*.py" scripts;


## Command Line Arguments

flow_sign_gen.py:
- arg1: (25,50,75,90), percentage of split train/test
- arg2: (zone,page), which trace to use for the signature
