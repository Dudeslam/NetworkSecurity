import os
from wordfreq import top_n_list
import pandas as pd
import string
import time
removed_singletons = {"b", "c", "d", "e", "f", "g", "h", "j", "k", "l","m", "n", 
                      "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"} 
  
top_list_words_list = [ele for ele in top_n_list("en", 1000) if ele not in removed_singletons]
top_list_words_list.append("conscience")
top_list_words_list.append("entirety,")
top_list_words_series = pd.Series(top_list_words_list)


def base_imports_and_conf(path_to_file1: str, path_to_file2: str) -> bytearray:
    file1 = bytearray(open(path_to_file1, 'rb').read())
    file2 = bytearray(open(path_to_file2, 'rb').read())
    # Set the length to be the smaller one
    size = len(file1) if len(file1) < len(file2) else len(file2)
    xord_bytes = bytearray(size)
    
    # XOR the files
    for i in range(size):
        xord_bytes[i] = file1[i] ^ file2[i]
        
    return xord_bytes

def get_mapper_dict(byte_array: bytearray, filtered_all_ascii: list):
    ascii_lookup_df = pd.DataFrame()
    for i in filtered_all_ascii[:100]:
        for q in filtered_all_ascii[:100]:
            ascii_lookup_df.loc[i, q] = ord(i) ^ ord(q)
    
    df = pd.DataFrame({"bytedata": byte_array}).set_index("bytedata")
    mapper_dict = {}
    for current_decimal in df.index:
        df_dummy = pd.DataFrame(columns=["from", "to"])
        focus_df = ascii_lookup_df[ascii_lookup_df == current_decimal]
        df_dummy["from"] = focus_df[focus_df.notnull()].stack().unstack().index
        df_dummy["to"] = focus_df[focus_df.notnull()].stack().unstack().columns
        mapper_dict[current_decimal] = df_dummy
    return mapper_dict, df

def print_mapning_and_input_f1_f2(input_string, mapper_dict, df):
        q=0
        b = []
        list_of_relevant_keys = df.index[:len(input_string)]
        for i in list_of_relevant_keys:
            mapper = mapper_dict[i]
            char = input_string[q]
            t = mapper[mapper["from"] == char]
            b.append(t.values[0])
            print("{}\t--> {}".format(i, t.values[0]))
            q= q+1
            
        
def run_one(series1, series2):
    x=0
    df_new = pd.DataFrame(columns=["col"])
    for i in series1:
        for q in series2:
            current_string = i+q
            splitted = current_string.split(" ")
            if (len(splitted) > 1) and (splitted[-1] == "") and (any(top_list_words_series == splitted[-2])):
                 df_new.loc[x, "col"] = current_string
            if any(top_list_words_series == current_string):
                 df_new.loc[x, "col"] = current_string
            else:
                if (" " in current_string):
                    splitted = current_string.split(" ")
                    if any(top_list_words_series.str.startswith(splitted[-1])) & (splitted[-1] != ""):
                        df_new.loc[x, "col"] = current_string
            x = x+1   
    return df_new

def convert_to_mapping(non_converted_string, df, mapper_dict):
    mapped_value = []
    chars = len(non_converted_string)
    for i in range(chars):
        bytenumber = df.index[i]
        df_temp = mapper_dict[bytenumber]
        mapped_value.append(
                df_temp[df_temp["from"] == non_converted_string[i]]["to"].values[0]
            )
        
    return "".join(mapped_value)
    

def convert_between_files(df, mapper_dict, working_dataframe):
    x=0
    df_new = pd.DataFrame(columns=["non_converted_string", "converted_string"])
    
    for i in working_dataframe["col"]: 
        
        current_string = convert_to_mapping(i, df, mapper_dict)
        splitted = current_string.split(" ")
        if (len(splitted) > 1) and (splitted[-1] == "") and (any(top_list_words_series == splitted[-2])):
             df_new.loc[x, "converted_string"] = current_string
             df_new.loc[x, "non_converted_string"] = i
        if any(top_list_words_series.str.startswith(splitted[-1])) and (splitted[-1] != ""):
             df_new.loc[x, "converted_string"] = current_string
             df_new.loc[x, "non_converted_string"] = i
        else:
            if (" " in current_string):
                splitted = current_string.split(" ")
                if any(top_list_words_series.str.startswith(splitted[-1])) & (splitted[-1] != ""):
                    df_new.loc[x, "converted_string"] = current_string
                    df_new.loc[x, "non_converted_string"] = i
        x = x+1
    return df_new

def get_decoding(number_of_bytes_to_decode, df_f1, mapper_dict, index_df):
    q = []
    p = []
    for i in range(number_of_bytes_to_decode):
        
        if q:
            dfn = q[i-1]
            print(i+1)
            print("df{} finished in: {}  seconds".format(i+1, round(time.time() - start_time), 5))
            dfn_f1 = run_one(dfn["col"], df_f1['from'].iloc[:, i+1].dropna())
            dfn_f2 = convert_between_files(index_df, mapper_dict, dfn_f1)
            df = dfn_f1[dfn_f1["col"].isin(dfn_f2["non_converted_string"])]                
            q.append(df) 
            p.append(dfn_f2)
        else:
            df1_f1 = run_one(df_f1['from'].iloc[:, 0].dropna(), df_f1['from'].iloc[:, 1].dropna()) 
            df1_f2 = convert_between_files(index_df, mapper_dict, df1_f1)
            df1 = df1_f1[df1_f1["col"].isin(df1_f2["non_converted_string"])]
            print("df1 finished in:  %s seconds" % (time.time() - start_time))
            q.append(df1)
            p.append(df1_f2)
    return q, p

if __name__ == '__main__':

    start_time = time.time()
  
    byte_array =  base_imports_and_conf(path_to_file1=os.getcwd() + "\\files\\challenge1.txt", 
                                        path_to_file2=os.getcwd() + "\\files\\challenge2.txt")
    all_ascii = list(string.printable)
    filtered_all_ascii = all_ascii[10:36] + all_ascii[73:75] + [all_ascii[62], all_ascii[63], all_ascii[68], all_ascii[94], all_ascii[77]]

    mapper_dict, index_df = get_mapper_dict(byte_array=byte_array, 
                                      filtered_all_ascii=filtered_all_ascii)
    f1 = []
    f2 = []
    for q in index_df.index:
        f1.append(mapper_dict[q]["from"])
        f2.append(mapper_dict[q]["to"])
    df_f1 = pd.concat(f1, axis=1)    
    df_f2 = pd.concat(f2, axis=1)    
    
    print("init finished in:  %s seconds" % (time.time() - start_time))    
    q, p = get_decoding(index_df.shape[0]-1, df_f1, mapper_dict, index_df)
    print(p[25])
