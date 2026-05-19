from math import nan
import pandas as pd
import numpy as np
import json 
#import pdfkit
import sys


RES_FOLDER = sys.argv[1] 
no_mod_times = pd.read_csv(RES_FOLDER + "no_module.csv")
# interpreters_times = pd.read_csv(RES_FOLDER + "interpreters.csv")
page_sync_times = pd.read_csv(RES_FOLDER + "page_sync.csv")
zone_sync_times = pd.read_csv(RES_FOLDER + "zone_sync.csv")
pin_times = pd.read_csv(RES_FOLDER + "pin.csv")
dinamo_times = pd.read_csv(RES_FOLDER + "dynamo.csv")
qemu_times = pd.read_csv(RES_FOLDER + "qemu.csv")

languages = no_mod_times["Language"].unique()
tests = no_mod_times["Test Name"].unique()

medians = {}
slowdown = {
    "Language":[],
    "Test Name":[],
    "Qemu":[],
    "Dynamo":[],
    "Pin":[],
    # "LKM Zone interpreters":[],
    "JITScanner":[],
    "LKM Zone sync check":[],
}
medians_c = {
    "Language":[],
    "Test Name":[],
    "Baseline":[],
    "Qemu":[],
    "Dynamo":[],
    "Pin":[],
    # "LKM Zone interpreters":[],
    "JITScanner":[],
    "LKM Zone sync check":[],
}
for l in languages:
    if medians.get(l) == None:
        medians[l] = {}
    for t in tests:
        # no_mod = np.median(np.array())
        # print(no_mod_times.loc[(no_mod_times["Test Name"] == t) & (no_mod_times["Language"] == l), ["Real Time"]])
        no_mod_med = np.median(np.array(no_mod_times.loc[
            (no_mod_times["Test Name"] == t) & (no_mod_times["Language"] == l), 
            ["Real Time"]]))

        pin_med = np.median(np.array(pin_times.loc[
            (pin_times["Test Name"] == t) & (pin_times["Language"] == l), 
            ["Real Time"]]))
        dinamo_med = np.median(np.array(dinamo_times.loc[
            (dinamo_times["Test Name"] == t) & (dinamo_times["Language"] == l), 
            ["Real Time"]]))
        qemu_med = np.median(np.array(qemu_times.loc[
            (qemu_times["Test Name"] == t) & (qemu_times["Language"] == l), 
            ["Real Time"]]))

        page_sync_med = np.median(np.array(page_sync_times.loc[
            (page_sync_times["Test Name"] == t) & (page_sync_times["Language"] == l), 
            ["Real Time"]]))
        # interpreters_med = np.median(np.array(interpreters_times.loc[
        #     (interpreters_times["Test Name"] == t) & (interpreters_times["Language"] == l), 
        #     ["Real Time"]]))
        zone_sync_med = np.median(np.array(zone_sync_times.loc[
            (zone_sync_times["Test Name"] == t) & (zone_sync_times["Language"] == l), 
            ["Real Time"]]))

        medians[l][t] = (no_mod_med, pin_med, dinamo_med, qemu_med, page_sync_med, zone_sync_med)

        if no_mod_med != nan:
            slowdown["Language"].append(l)
            slowdown["Test Name"].append(t)
            slowdown["Pin"].append((pin_med-no_mod_med)/no_mod_med)
            slowdown["Dynamo"].append((dinamo_med-no_mod_med)/no_mod_med)
            slowdown["Qemu"].append((qemu_med-no_mod_med)/no_mod_med)
            # slowdown["LKM Zone interpreters"].append((interpreters_med-no_mod_med)/no_mod_med)
            slowdown["JITScanner"].append((page_sync_med-no_mod_med)/no_mod_med)
            slowdown["LKM Zone sync check"].append((zone_sync_med-no_mod_med)/no_mod_med)
            
            medians_c["Language"].append(l)
            medians_c["Test Name"].append(t)
            medians_c["Baseline"].append(no_mod_med)
            medians_c["Pin"].append(pin_med)
            medians_c["Dynamo"].append(dinamo_med)
            medians_c["Qemu"].append(qemu_med)
            medians_c["JITScanner"].append(page_sync_med)
            # medians_c["LKM Zone interpreters"].append(interpreters_med)
            medians_c["LKM Zone sync check"].append(zone_sync_med)
               
      
        # print(f"LANGUAGE: {l}, TEST: {t} --> PAGE_SYNC: ${(page_sync_med-no_mod_med)/no_mod_med*100:.2f}% - ZONE_SYNC: ${(zone_sync_med-no_mod_med)/no_mod_med*100:.2f}%")
    
# print(json.dumps(medians, indent=1))
print([len(medians_c[k]) for k in medians_c.keys()])
medians_pd = pd.DataFrame(medians_c)

print(medians_pd)

slow_pd = pd.DataFrame(slowdown)

print(slow_pd)

slow_pd.to_csv("slowdown_{}.csv".format(slow_pd["Language"].unique()[0]))
