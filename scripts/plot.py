import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def slice_per(source, step):
    return [source[i:i+step] for i in range(0, len(source), step)]


def read_mutation_log(filename):
    f = open(filename, "r")
    content = f.read()
    content = content.replace("}\n2023", "}~fz2023")
    lst = content.split("~fz")
    sliced_lst = slice_per(lst[0:], 8)
    dataframe = pd.DataFrame(sliced_lst)
    colnames = ['timestamp', 'parent_id', 'parent_input', 'cur_input', 'result', 'mutation_dist', 'parent_cov', 'cur_cov']
    dataframe.columns = colnames
    return dataframe


df = read_mutation_log("mutation.1.log")

f = open('mutation_1_diff.txt', 'r')
coverage = f.read()
coverage = coverage.split(',')
coverage = coverage[:-1]
coverage = np.asarray(coverage).astype(int)

# result = df['result'].to_numpy()
mutation_dist = df['mutation_dist'].to_numpy().astype(int)

# Plotting mutation distance vs coverage distance
f1 = plt.figure(1)

plt.plot(mutation_dist, coverage, '.')

plt.xlabel('Mutation Distance')
plt.ylabel('Coverage Distance')
plt.title('Coverage Distance in Terms of Mutation Distance')

x_low = int(min(mutation_dist))
x_high = int(max(mutation_dist))
y_low = int(min(coverage))
y_high = int(max(coverage))


plt.xticks(np.arange(x_low, x_high, (x_high-x_low)/10))
plt.yticks(np.arange(y_low, y_high, (y_high-y_low)/10))
# plt.axis([-50, 2000, -50, 1000])
plt.grid(True)
plt.show()

# Plotting mutation distance vs coverage distance while differentiating semantic validity
