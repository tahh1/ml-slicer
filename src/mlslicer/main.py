import os
import ast
import astunparse
import time
import traceback
import logging
from mlslicer.global_collector import GlobalCollector
from mlslicer import factgen
from mlslicer.irgen import CodeTransformer
from mlslicer.config import configs
from mlslicer.utils import remove_files
from mlslicer.build_subgraphs import build_subgraphs
from pathlib import Path
import subprocess
try:
    # Python 3.9+
    from importlib.resources import files
except ImportError:
    # Python 3.8
    from importlib_resources import files

logger = logging.getLogger(__name__)


PACKAGE_ROOT = Path(__file__).resolve().parent

PYWRITE_DIR = PACKAGE_ROOT  / "pywrite"


def time_decorator(func):
    def wrapper_function(*args, **kwargs):
        try:
            st = time.time()
            ret = func(*args,  **kwargs)
            ed = time.time()
            return ret, ed - st
        except Exception as e:
            logger.error("Failed to run %s: %s", func.__name__, e)
            logger.debug("Traceback for %s:\n%s", func.__name__, traceback.format_exc())
            return None, -1
    return wrapper_function

@time_decorator
def load_input(input_path):
    with open(input_path) as f:
        code = f.read()
        tree = ast.parse(code)
    return tree

@time_decorator
def ir_transform(tree, ir_path):
    ignored_vars = GlobalCollector().visit(tree)
    v = CodeTransformer(ignored_vars)
    new_tree = v.visit(tree)
    new_code = astunparse.unparse(new_tree)
    with open(ir_path, "w") as f:
        f.write(new_code)
    return new_tree

@time_decorator
def infer_types(ir_path, verbose: bool = False):
    cmd = [
        "timeout", "5m",
        "node", configs.inference_path,
        ir_path,
        "--lib",
    ]
    ret = subprocess.run(cmd, capture_output=True, text=True)
    if verbose:
        if ret.stdout:
            logger.info("Type inference stdout:\n%s", ret.stdout.rstrip())
        if ret.stderr:
            logger.warning("Type inference stderr:\n%s", ret.stderr.rstrip())
    if ret.returncode != 0:
        if ret.stderr:
            logger.warning("Type inference error:\n%s", ret.stderr.rstrip())


def generate_lineno_mapping(tree1, tree2):
    lineno_map = {}

    if len(tree1.body) != len(tree2.body):
        return lineno_map

    def add_to_mapping(body1, body2):
        for stmt1, stmt2 in zip(body1, body2):
            if hasattr(stmt1, 'lineno') and hasattr(stmt2, 'lineno'):
                lineno_map[str(stmt2.lineno)] = str(stmt1.lineno)

            # Heuristic: Handle control constructs like else/finally/except
            for attr in ['orelse', 'finalbody', 'handlers']:
                if hasattr(stmt1, attr) and hasattr(stmt2, attr):
                    part1 = getattr(stmt1, attr)
                    part2 = getattr(stmt2, attr)

                    if isinstance(part1, list) and isinstance(part2, list):
                        # Infer the control keyword line number
                        if part1 and part2:
                            # Only if both have at least one statement
                            stmt1_line = part1[0].lineno - 1
                            stmt2_line = part2[0].lineno - 1
                            if stmt2_line > 0 and stmt1_line > 0:
                                lineno_map[str(stmt2_line)] = str(stmt1_line)

                        add_to_mapping(part1, part2)

            # Regular body mapping
            if hasattr(stmt1, 'body') and hasattr(stmt2, 'body'):
                add_to_mapping(stmt1.body, stmt2.body)

    add_to_mapping(tree1.body, tree2.body)
    return lineno_map


@time_decorator
def generate_facts(tree, json_path, fact_path):
    f = factgen.FactGenerator(json_path)
    f.visit(tree)

    for fact_name, fact_list in f.FManager.datalog_facts.items():
        with open(os.path.join(fact_path, fact_name + ".facts"), "w") as f:
            facts = ["\t".join(t) for t in fact_list]
            f.writelines("\n".join(facts))

@time_decorator
def datalog_analysis(fact_path, verbose: bool = False):
    fact_path = Path(fact_path).resolve()

    # Resolve main.dl from the installed package
    datalog_file = (
        files("mlslicer")
        .joinpath("datalog/main.dl")
    )

    # Use subprocess instead of os.system (safer, clearer)
    cmd = [
        "timeout", "5m",
        "souffle",
        str(datalog_file),
        "-F", str(fact_path),
        "-D", str(fact_path),
    ]

    ret = subprocess.run(cmd, capture_output=True, text=True)
    if verbose:
        if ret.stdout:
            logger.info("Soufflé stdout:\n%s", ret.stdout.rstrip())
        if ret.stderr:
            logger.warning("Soufflé stderr:\n%s", ret.stderr.rstrip())
    if ret.returncode != 0:
        if ret.stderr:
            logger.warning("Soufflé failed:\n%s", ret.stderr.rstrip())
        raise TimeoutError("Soufflé datalog analysis timed out or failed")
  
@time_decorator    
def build_graphs(fact_path,ir_path,input_path):
    build_subgraphs(fact_path=fact_path,ir_path=ir_path,input_path=input_path)
    


def main(input_path, output_dir, verbose: bool = False):
    ir_path = os.path.join(output_dir, os.path.basename(input_path) +".ir.py")
    json_path = os.path.join(output_dir, os.path.basename(input_path) + ".json")
    fact_path = os.path.join(output_dir, os.path.basename(input_path)[:-3] + "-fact")
    t = [None]*7

    tree, t[0] = load_input(input_path)
    if t[0] == -1:
        logger.error("Failed to parse: %s", input_path)
        return "Failed to parse"
    
    tree, t[1] = ir_transform(tree, ir_path)
    if t[1]== -1:
        logger.error("Failed to generate IR: %s", input_path)
        return "Failed to generate IR"
    
    
    
    _, t[2] = infer_types(ir_path, verbose=verbose)
    if not os.path.exists(json_path):
        logger.error("Failed to infer types: %s", input_path)
        return "Failed to infer types" 

    
    newtree, t[3] = load_input(ir_path)
    if t[3] == -1:
        logger.error("Failed to parse transformed file: %s", input_path)
        return "Failed to parse transformed file"

    # clean facts
    if not os.path.exists(fact_path):
        os.makedirs(fact_path)
    else:
        remove_files(fact_path)

    if configs.output_flag:
        lineno_map = generate_lineno_mapping(tree, newtree)
        with open(os.path.join(fact_path, "LinenoMapping.facts"), "w") as f:
            facts = [a + "\t" + b for a, b in lineno_map.items()]
            f.writelines("\n".join(facts))
    
    _, t[4] = generate_facts(newtree, json_path, fact_path)
    if t[4] == -1:
        logger.error("Failed to generate facts: %s", input_path)
        return "Failed to generate facts" 
    
    _, t[5] = datalog_analysis(fact_path, verbose=verbose)
    if t[5] == -1:
        logger.error("Failed to analyze: %s", input_path)
        return "Failed to analyze" 
        
        
    _, t[6] = build_graphs(fact_path,ir_path,input_path)
    
    logger.info(
        "Success!\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f",
        t[0] + t[1] + t[3] + t[4],
        t[2],
        t[5],
        t[6],
        sum(t),
    )
    return t
