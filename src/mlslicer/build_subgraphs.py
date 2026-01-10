import pandas as pd
import numpy as np
import re
import torch
import os
import networkx as nx
import logging
from mlslicer.utils import remove_files
import ast
import astor

logger = logging.getLogger(__name__)

INVALID_VAR_PATTERN = re.compile(r"\[(\$?invo\d+?)?, (\$?invo\d+?)?\]")
INSTR_NUMBER_PATTERN = r'(?<=\])\d+'

def extract_instr_and_vars(FlowVarTransformation,FlowVarStoreIndex):

    unique_instr = sorted(set(
                            read_index_or_empty(FlowVarTransformation,"InstructionId")
                            +read_index_or_empty(FlowVarStoreIndex,"InstructionId")))
    index_mapping = {instr:index for index,instr in enumerate(unique_instr)}
    unique_vars = sorted(set(
                           read_index_or_empty(FlowVarTransformation,"ToId")+
                           read_index_or_empty(FlowVarTransformation,"FromId")+
                           read_index_or_empty(FlowVarStoreIndex,"ToId")+
                           read_index_or_empty(FlowVarStoreIndex,"FromId")))
    unique_vars = list(filter(lambda x: INVALID_VAR_PATTERN.fullmatch(x)==None,unique_vars)) #Filter empty vars ([, ])
    num_instr= len(index_mapping)
    for index,var in enumerate(unique_vars):
        index_mapping[var]=num_instr+index

    return unique_instr,unique_vars,index_mapping


def preprocess_flow_df(df):
     df["To"]=df["To"].fillna("")
     df["From"]=df["From"].fillna("")
     df["InstructionId"] = df["ToCtx"] + df["Instr"].astype(str) + df["FromCtx"]
     df["ToId"] = df["To"] + df["ToCtx"]
     df["FromId"] = df["From"] + df["FromCtx"]
     return df


def process_flow_df(df, lines,
                    instr_labels, instr_meths, instr_loc,
                    flow_from_inst, flow_to_inst,
                    var_loc, var_labels):
    for _, row in df.iterrows():
        instr_id = row["InstructionId"]
        to_id = row["ToId"]
        from_id = row["FromId"]

        if instr_id not in instr_labels:
            instr_labels[instr_id] = ' '.join(row["tag"].split()[:2])
            instr_meths[instr_id] = row["meth"]
            instr_loc[instr_id] = lines[int(re.findall(INSTR_NUMBER_PATTERN, instr_id)[0]) - 1]

        if not INVALID_VAR_PATTERN.fullmatch(to_id):
            flow_from_inst[instr_id].append(to_id)
            var_loc[to_id] = lines[int(re.findall(INSTR_NUMBER_PATTERN, instr_id)[0]) - 1]

        if not INVALID_VAR_PATTERN.fullmatch(from_id):
            flow_to_inst[instr_id].append(from_id)
            if from_id not in var_labels:
                var_labels[from_id] = ' '.join(row["tag"].split()[2:])


def process_telemetry_df(telemetry_df):
    telemetry_df['TrainInstr']=telemetry_df['TrainCtx']+telemetry_df['TrainLine'].astype(str)+telemetry_df['TrainCtx']
    telemetry_df['TestInstr']=telemetry_df['TestCtx']+telemetry_df['TestLine'].astype(str)+telemetry_df['TestCtx']
    telemetry_df['TrainVar']=telemetry_df['TrainData']+telemetry_df['TrainCtx']
    telemetry_df['TestVar']=telemetry_df['TestData']+telemetry_df['TestCtx']
    return telemetry_df


def build_features_df(index_mapping,instr_labels,var_labels,instr_meths,var_loc,instr_loc):
    # Creating the features dataframe
    labels = pd.DataFrame(index=range(len(index_mapping)),columns=['Nodes', 'Labels', 'Code','Method'])
    for key, value in instr_labels.items():
        labels.iloc[index_mapping[key]] = {'Nodes': key, 'Labels': value, 'Code': instr_loc[key] if key in instr_loc.keys() else "", 'Method':instr_meths[key] if 'NonLocalMethod' in value else ""}
    for key, value in var_labels.items():
        labels.iloc[index_mapping[key]] = {'Nodes': key, 'Labels': value, 'Code': var_loc[key] if key in var_loc.keys() else "", 'Method':instr_meths[key] if 'NonLocalMethod' in value else ""}

    labels.fillna("",inplace=True)
    return labels

    
def find_node_by_line(tree, line_number,file):
    for node in ast.walk(tree):
        if hasattr(node, 'lineno') and node.lineno == line_number+1:
            return node
    if("else" not in file[line_number]):
        logger.debug("Node not found: %s", file[line_number])
    return None

def build_adj(flow_from_inst,flow_to_inst, unique_instr,unique_vars,index_mapping):

    adj= np.zeros((len(unique_instr)+len(unique_vars),len(unique_instr)+len(unique_vars)))
    for index,instr in enumerate(unique_instr):
        for to_vars in flow_from_inst[instr]:
            adj[index][index_mapping[to_vars]]=1
        for from_vars in flow_to_inst[instr]:
            adj[index_mapping[from_vars]][index]=1

    return adj


def get_columns(filename):
    d = {
        "FLowVarTransformation.csv": ['To', 'ToCtx', 'Instr', 'From','FromCtx', 'tag', 'meth', 'FromIdx', 'ToIdx'],
        "Telemetry_ModelPair.csv": ['TrainModel','TrainData','TrainInvo','TrainLine','TrainMethod','TrainCtx',
                                    'TestModel','TestData','TestInvo','TestLine','TestMethod','TestCtx'],
        "InvokeInjected.csv":['Invocation','Method','InMeth'],
        "FLowVarStoreIndex.csv": ['To', 'ToCtx', 'Instr', 'From','FromCtx', 'tag', 'meth', 'FromIdx', 'ToIdx'],
        "LocalMethod.facts": ['MethodName','StartLineno','EndLineno','bool'],
        "LinenoMapping.facts": ['OriginalLineno','IRLineno'],
        "LocalClass.facts": ['ClassNameName','StartLineno','EndLineno'],
        "With.facts" : ['StartLineno','EndLineno']

    }
    
    return d[filename]

def read_csv_or_empty(fact_path,filename):

    filepath= os.path.join(fact_path,filename)
    if os.path.exists(filepath):
        return pd.read_csv(filepath, sep="\t", names=get_columns(filename))
    else:
        return pd.DataFrame()



def read_index_or_empty(df,index):

    if df.empty:
        return []
    else:
        return list(df[index])
    

def match_invo(label,injected_invos):
    numbers = re.findall(r"\d+", label)
    strings = re.split(r"\d+",label)
    new_numbers = []
    for number in numbers:
        shift = sum(1 for el in injected_invos if el < int(number))
        new_numbers.append(str(int(number)-shift))
    new_label = ""
    for i,string in enumerate(strings):
      new_label += string
      if(i<len(strings)-1):
        new_label += new_numbers[i]
    return new_label


def extract_num_or_flag(node):
    if re.search(INSTR_NUMBER_PATTERN,node) != None:
        return int(re.search(INSTR_NUMBER_PATTERN,node).group(0))-1
    else:
        return -1

def get_leading_spaces(old_code):
    return len(old_code.expandtabs(8)) - len(old_code.expandtabs(8).lstrip())

def indent_string(s, num_spaces):
    tabs = num_spaces//8
    spaces = num_spaces - tabs*8
    indentation = '\t' * tabs + ' '*spaces
    return '\n'.join(indentation + line for line in s.splitlines())

def extract_and_save_snippet(ir_path,input_path,instructions,fact_path,output_name,telemtry_row):
    locals = read_csv_or_empty(fact_path,"LocalMethod.facts")
    mappings = read_csv_or_empty(fact_path,"LinenoMapping.facts")
    classes = read_csv_or_empty(fact_path,"LocalClass.facts")
    withs = read_csv_or_empty(fact_path,"With.facts")
    pairs = []


    for i,row in locals.iterrows():
         pairs.append([row['StartLineno'],row['EndLineno'],bool(row['bool'])])
    for i,row in classes.iterrows():
         pairs.append([row['StartLineno'],row['EndLineno'],False])
    for i,row in withs.iterrows():
         pairs.append([row['StartLineno'],row['EndLineno'],False])

    
    to_add = set()
    for inst in instructions:
        for pair in pairs:
            if inst>pair[0]-1 and inst<=pair[1]-1:
                if(pair[2]):
                    to_add.add(pair[0]-1)
                    to_add.add(pair[1]-1)
                else:
                    to_add.add(pair[0]-1)

    instructions.extend(list(to_add))  
    mapping = {row['OriginalLineno']-1:row['IRLineno']-1 for i,row in mappings.iterrows()}
    new_instructions= [mapping[i] if i in mapping.keys() else -1 for i in instructions]
    
    instructions = sorted(list(set(instructions)))  
    new_instructions = sorted(list(set(new_instructions)))  

    file_ir = open(ir_path, 'r')
    file = open(input_path, 'r')
    snippet_ir = open(os.path.join(f"{fact_path}/_snippets",f'{output_name}.py'),"w")
    snippet = open(os.path.join(f"{fact_path}/_snippets",f'{output_name}_original.py'),"w")
    snippet_to_original = open(os.path.join(f"{fact_path}/_snippets",f'{output_name}_mapping.fact'),"w")
    
    file_ir = file_ir.read()
    file_ir = file_ir.splitlines()

    file = file.read()
    tree = ast.parse(file)
    file = file.splitlines()
    for inst in instructions:
        if inst != -1:
            snippet_ir.write(f"{file_ir[inst]}\n")
            
    original_to_snippet = {}
    for i,inst in enumerate(new_instructions):
         if inst != -1:
             snippet_to_original.write(f"{i}\t{inst+1}\n")
             original_to_snippet[inst+1]=i
             node = find_node_by_line(tree, inst,file)
             if(node != None and (isinstance(node,ast.Assign) or (isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) ) or isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef)) ):                 
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # Build only the method header
                    args = [a.arg for a in node.args.args]
                    defaults = len(node.args.defaults)
                    non_defaults = len(args) - defaults

                    # Add defaults if needed
                    header_parts = []
                    for idx, arg in enumerate(args):
                        if idx < non_defaults:
                            header_parts.append(arg)
                        else:
                            default_obj = node.args.defaults[idx - non_defaults]
                            header_parts.append(f"{arg}={astor.to_source(default_obj).strip()}")

                    arglist = ", ".join(header_parts)
                    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
                    new_code = f"{prefix} {node.name}({arglist}):"
                 else:
                    new_code = astor.to_source(node)
                    old_code = file[inst]
                    num_spaces = get_leading_spaces(old_code.rstrip())

                 new_code = indent_string(new_code.rstrip("\n"), num_spaces)
                 snippet.write(f"{i} {new_code}\n")
             else:
                 snippet.write(f"{i} {file[inst]}\n")

    #print(original_to_snippet)
    #print(mapping)
    #print(telemtry_row)
    try:
        telemetry_info_snippet = {"TrainMethod": [telemtry_row["TrainMethod"]],"TrainLine": [original_to_snippet[mapping[telemtry_row["TrainLine"]-1]+1]],
                                "TestMethod": [telemtry_row["TestMethod"]],"TestLine": [original_to_snippet[mapping[telemtry_row["TestLine"]-1]+1]]}
        df = pd.DataFrame(data=telemetry_info_snippet)
        df.to_csv(os.path.join(f"{fact_path}/_snippets",f'{output_name}_snippet_model_info.csv'),sep="\t",header=False,index=False)
    except KeyError:
        logger.warning("Some of the code lives inside an unreachable block by the analysis")


def build_subgraphs(fact_path,ir_path,input_path):
    
    #Readind necessary files
    FlowVarTransformation= read_csv_or_empty(fact_path,"FLowVarTransformation.csv")
    FlowVarStoreIndex= read_csv_or_empty(fact_path,"FLowVarStoreIndex.csv")
    df_injected= read_csv_or_empty(fact_path,"InvokeInjected.csv")
    df_telemetry_model_pair= read_csv_or_empty(fact_path,"Telemetry_ModelPair.csv")

    #Reading the IR file
    try:
        with open(ir_path, 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        logger.error("File not found: %s", ir_path)
        raise
    except Exception as e:
        logger.exception("An error occurred while reading IR file: %s", e)
        raise


    #Making sure there are models detected and dataflows
    if(df_telemetry_model_pair.empty==True or FlowVarTransformation.empty==True):
        return 
    if(FlowVarStoreIndex.empty==False):
            FlowVarStoreIndex= preprocess_flow_df(FlowVarStoreIndex)
    df_telemetry_model_pair= process_telemetry_df(df_telemetry_model_pair)
    FlowVarTransformation= preprocess_flow_df(FlowVarTransformation)
    


    #Creating the graphs folder
    if not os.path.exists(os.path.join(fact_path,'_snippets')):
        os.makedirs(os.path.join(fact_path,'_snippets'))
        logger.info("Created %s", fact_path + "/_snippets")
    else:
        remove_files(os.path.join(fact_path,'_snippets'))
    graph_paths= os.path.join(fact_path,"_snippets")


    # Extracting the set of unique instructions and vars 
    unique_instr,unique_vars,index_mapping = extract_instr_and_vars(FlowVarTransformation,FlowVarStoreIndex)



    # Storing data flows in a dict
    flow_from_inst={ instr:[] for instr in unique_instr}
    flow_to_inst={instr:[] for instr in unique_instr}
    instr_labels={}
    instr_loc={}
    instr_meths={}
    var_loc={}
    var_labels={}
    process_flow_df(FlowVarTransformation, lines,
                    instr_labels, instr_meths, instr_loc,
                    flow_from_inst, flow_to_inst, var_loc, var_labels)
    process_flow_df(FlowVarStoreIndex, lines,
                    instr_labels, instr_meths, instr_loc,
                    flow_from_inst, flow_to_inst, var_loc, var_labels)
    flow_from_inst = {instr:list(set(vars)) for instr,vars in flow_from_inst.items()}
    flow_to_inst = {instr:list(set(vars)) for instr,vars in flow_to_inst.items()}



    

    #Building the overall data flow graph 
    adj=build_adj(flow_from_inst,flow_to_inst, unique_instr,unique_vars,index_mapping)
    num_nodes = adj.shape[0]
    G = nx.DiGraph()
    G.add_nodes_from(range(num_nodes))
    rows, cols = np.where(adj > 0)
    for u, v in zip(rows.tolist(), cols.tolist()):
        G.add_edge(u, v)



    #Building the labels features
    labels = build_features_df(index_mapping,instr_labels,var_labels,instr_meths,var_loc,instr_loc)
    instr_nodes_nums = torch.tensor(list(map(lambda node:extract_num_or_flag(node),labels["Nodes"])))
    labels_list = instr_nodes_nums.tolist()
    for node_id, label in enumerate(labels_list):
        G.nodes[node_id]["labels"] = label

    #Building the per-TTI subgraphs
    injected_invos = list(map(lambda x : int(re.search(r"\d+", x).group()), df_injected["Invocation"])) if df_injected.empty == False else []
    missing_pairs = 0
    for index,row in df_telemetry_model_pair.iterrows():
        original=row['TrainInvo']+"_"+row['TestInvo']+"_"+row['TrainCtx']+"_"+row['TestCtx']
        original = match_invo(original,injected_invos) if len(injected_invos)>0 else original
        pair = [row['TrainInstr'],row['TestInstr']]
        try:
            pair_node_id = list(map(lambda x: index_mapping[x],pair))
        except KeyError:
            missing_pairs += 1
            continue

        seed_nodes = pair_node_id
        included = set(seed_nodes)
        for s in seed_nodes:
            included |= nx.ancestors(G, s)

        sg_nx = G.subgraph(included).copy()

        _ID_ordered = []
        visited = set()

        for s in seed_nodes:
            if s in included and s not in visited:
                _ID_ordered.append(s)
                visited.add(s)

        from collections import deque
        for s in seed_nodes:
            if s not in included:
                continue

            q = deque([s])
            local_seen = set([s])

            while q:
                u = q.popleft()
                for v in sg_nx.predecessors(u):
                    if v in included and v not in local_seen:
                        local_seen.add(v)
                        q.append(v)

                        if v not in visited:
                            _ID_ordered.append(v)
                            visited.add(v)

        for n in sorted(included):
            if n not in visited:
                _ID_ordered.append(n)
                visited.add(n)

        mapping = {old_id: new_id for new_id, old_id in enumerate(_ID_ordered)}

        relabeled_sg = nx.DiGraph()
        relabeled_sg.add_nodes_from(range(len(_ID_ordered)))
        for u, v in sg_nx.edges():
            relabeled_sg.add_edge(mapping[u], mapping[v])

        for new_id, old_id in enumerate(_ID_ordered):
            relabeled_sg.nodes[new_id]["_ID"] = old_id
            relabeled_sg.nodes[new_id]["labels"] = G.nodes[old_id]["labels"]

        instructions = [
            relabeled_sg.nodes[i]["labels"]
            for i in range(relabeled_sg.number_of_nodes())
        ]
        extract_and_save_snippet(ir_path,input_path,instructions=instructions,fact_path=fact_path,output_name=original,telemtry_row=row)    
    if missing_pairs > 0:
        logger.warning("Skipped %d model pairs not found in index mapping", missing_pairs)





        



    
