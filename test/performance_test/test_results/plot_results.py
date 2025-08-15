import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

GRAPH_TYPE = "PHP"

colors = ["#03045e", "#023e8a", "#0077b6", "#0096c7", "#00b4d8", "#48cae4", "#90e0ef"]

#################### only change this #########################
RES_FOLDER = "../csv_tests/1709984739_test/"

no_mod_times = pd.read_csv(RES_FOLDER + "no_module.csv")
page_sync_times = pd.read_csv(RES_FOLDER + "page_sync.csv")
zone_sync_times = pd.read_csv(RES_FOLDER + "zone_sync.csv")


times = [0]*3

times[0] = no_mod_times.loc[(no_mod_times["Language"] == GRAPH_TYPE)]
times[1] = page_sync_times.loc[(page_sync_times["Language"] == GRAPH_TYPE)]
times[2] = zone_sync_times.loc[(zone_sync_times["Language"] == GRAPH_TYPE)]

# test_names = no_mod_times["Test Name"].unique()
 
save_name = f"{GRAPH_TYPE}_execution_time.pdf"
y_name = "Average Execution Time (s)"
x_name = "Test Name"
labels = ["No LKM", "LKM with page synch check", "LKM with zone synch check"]     
ys = []
for time in times:
    ys.append(np.array(np.divide(time["Real Mean Time"], time["Executions"])))

errs = []
for time in times:    
    errs.append(np.array(np.divide(time["Real Var Time"], time["Executions"])))

xs = times[0]["Test Name"].tolist()
colors = [colors[0], colors[3], colors[6]]

###############################################################


#err_bar_color = "#d62828"
#err_bar_color = "#778da9"
err_bar_color = "#b5179e"
err_bar_color = "#e63946"

if (len(ys) < 4):
    barWidth = 0.25
else:
    barWidth = 0.12
barSpace = 0.01
br = [] 
br.append(np.arange(len(ys[0])))
for i in range(0, len(ys)-1):    
    br.append([x + barWidth + barSpace for x in br[-1]])
#br3 = [x + barWidth + barSpace for x in br2]
#br4 = [x + barWidth + barSpace for x in br3]
#br5 = [x + barWidth + barSpace for x in br4]

for i in range(0, len(ys)):
    plt.bar(br[i], ys[i], color =colors[i], width = barWidth, label=labels[i],yerr = np.sqrt(errs[i]), error_kw=dict(ecolor=err_bar_color, lw=1.5, capsize=3, capthick=1.5))
    #plt.bar(br2, ys[1], color =colors[1], width = barWidth, label=labels[1],yerr = np.sqrt(errs[1]), error_kw=dict(ecolor=err_bar_color, lw=1.5, capsize=3, capthick=1.5))
    #plt.bar(br3, ys[2], color =colors[3], width = barWidth, label=labels[2],yerr = np.sqrt(errs[2]), error_kw=dict(ecolor=err_bar_color, lw=1.5, capsize=3, capthick=1.5))

plt.xlabel(x_name)
plt.ylabel(y_name)
plt.xticks([r + barWidth + 20*barSpace for r in range(len(ys[0]))], xs)
plt.legend()
#plt.title("Students enrolled in different courses")
plt.savefig(save_name)
plt.show()