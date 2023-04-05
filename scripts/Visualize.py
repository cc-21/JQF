import pandas as pd
import numpy as np
import matplotlib.pyplot as plt


def slice_per(source, step):
    return [source[i:i+step] for i in range(0, len(source), step)]


# Merge two dictionaries, while keeping the sum of matching keys
def mergeDictionary(dict_1, dict_2):
    dict_3 = {**dict_1, **dict_2}
    for key, value in dict_3.items():
        if key in dict_1 and key in dict_2:
            dict_3[key] = dict_1[key] + dict_2[key]
    return dict_3


# Calculate the coverage of an input compared to its parent
def compareCoverage(parent, child):
    dict_3 = {**parent, **child}
    coverage = 0
    for key, value in dict_3.items():
        if key in parent and key in child:
            coverage += child[key] / (child[key] + parent[key])
        elif key in parent and key not in child:
            coverage -= parent[key]
        elif key in child and key not in parent:
            coverage += child[key]
    return coverage


def string_to_dict(dict_str):
    dict2 = {}
    if (dict_str.find("{")==-1):
        raise Exception("string_to_dict Exception: the supplied string is too short")
    dict_str = dict_str[dict_str.find("{")+1:dict_str.find("}")]
    pages = dict_str.split(", ")
    for page in pages:
        key, value = page.split("=")
        try:
            dict2[int(key)] = int(value)
        except ValueError:
            print("Something wrong with int()")
            print("value = " + value)
            print("key = " + key)
            continue
    return dict2


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


file_name = "mutation.1.log"
f = open(file_name, "r")
content = f.read()
# print(content[content.find("}\n")-10:content.find("}\n")+10])
content = content.replace("}\n2023", "}~fz2023")
lst = content.split("~fz")
sliced_lst = slice_per(lst[0:], 8)
# print("timestamp length:", len(lst[0]))
# print("timestamp format:", lst[0])

df = pd.DataFrame(sliced_lst)
# df.head(5)

colnames=['timestamp', 'parent_id', 'parent_input', 'cur_input', 'result', 'mutation_dist', 'parent_cov', 'cur_cov']
df.columns=colnames

# colnames = ['timestamp', 'idk', 's', 'input', 'exe_status', 'mutation_distance', 'idk2', 'coverage_map']
# data = pd.read_csv("mutation.log", sep='~fz ', names=colnames, engine='python');
# print(data.shape)
# print(data.head(10))



"""
result = {}
cov = {}
same=0

for input in range(10): #len(data)
    print('Input #{}'.format(input))
#     result.append({})
    string = data.iloc[input,4]
    if len(string)<5:
        continue
    elif string!="cov:s":
        string = string[5:-1]  # remove curly braces at beginning and end
        items = string.split(", ")  # split string into key-value pairs
#         same=0
        for item in items:
            key, value = item.split("=")
            cov[int(key)] = int(value)
#     elif string=="cov:s":
#         same+=1
     
    result = mergeDictionary(result, cov)

print(result)
"""

# Let's calculate the coverage for each input
parent = {}
child = {}
diff = np.zeros(len(df), dtype=int)

for i in range(len(df)):  # len(data)
    child_str = df.iloc[i, 7]   # 7 = 'cur_cov'
    if (df.iloc[i, 6].find('s') == -1):  # 6 = 'parent_cov'
        parent = string_to_dict(df.iloc[i, 6])

    if len(child_str) < 5:
        diff[i] = compareCoverage(parent, {})
        continue
    elif child_str != "c:{}":
        child = string_to_dict(child_str)
    elif child_str == "c:s":
        diff[i] = 0
        continue


    diff[i] = compareCoverage(parent, child)

# print(diff)


result = df['result'].to_numpy()
mutation_dist = df['mutation_dist'].to_numpy()

# Plotting mutation distance vs coverage distance
f1 = plt.figure(1)

plt.plot(mutation_dist, diff, '.')

plt.xlabel('Mutation Distance')
plt.ylabel('Coverage Distance')
plt.title('Coverage Distance in Terms of Mutation Distance')

# plt.axis([-50, 2000, -50, 1000])
plt.grid(True)

# Plotting mutation distance vs coverage distance while differentiating semantic validity










