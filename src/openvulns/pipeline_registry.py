"""Project pipelines."""
from typing import Dict

from kedro.framework.project import find_pipelines
from kedro.pipeline import Pipeline
import pandas as pd
import os
import logging


def register_pipelines() -> Dict[str, Pipeline]:
    """Register the project's pipelines.

    Returns:
        A mapping from pipeline names to ``Pipeline`` objects.
    """
    pipelines = find_pipelines()
    pipelines["__default__"] = sum(pipelines.values())
    return pipelines


def get_sanctuary_functions(parameters) -> pd.DataFrame:
    """
    Retrieve all functions from the sanctuary repo, iterate over .sol files and
    call extract_sanctuary_functions to get the functions
    :param parameters: directory where the sanctuary mainnet path
    :return: pd.DataFrame
    """
    logger = logging.getLogger(__name__)
    functions_all = []
    # counter to control the number of files to process
    cc = 0
    sanctuary_dir = parameters["sanctuary_dir"]
    repo_dir = parameters["repo_dir"]
    repo_url = parameters["repo_url"]
    for root, dirs, files in os.walk(sanctuary_dir):
        print(f"Processing {root} with {len(files)} files")
        try:
            for file in files:
                cc += 1
                if not file.endswith(".sol"):
                    continue
                with open(os.path.join(root, file), "r") as f:
                    lines = f.readlines()
                    function_onesource_df = extract_sanctuary_functions(
                        lines,
                        start_line=None,
                        source=os.path.join(root, file).replace(repo_dir, repo_url),
                    )
                    functions_all.append(function_onesource_df)
                # if len(functions_all) % 200000 == 0:
                #     func_df = pd.concat(functions_all)
                #     functions_all = [] reset and save
                if cc > 10:
                    print(f"Processed {cc} files, breaking")
                    break
        except Exception as e:
            logger.warning(e)
            continue
        if cc > 10:
            print(f"Processed {cc} files, breaking cc")
            break

    # 101,081 files
    # print(f"len{len(functions_all)}, {type(functions_all)}")
    # print(pd.concat(functions_all).head())
    functions_df = pd.concat(functions_all)
    logger.info(f"functions_df in get sanctuary functions: {functions_df.shape}")
    return functions_df


def extract_sanctuary_functions(solidity_code, vulnerable_line, source):
    lines = solidity_code[vulnerable_line:] if vulnerable_line else solidity_code
    inside_function = False
    start_line = 0
    # Initialize a stack to keep track of opening and closing braces
    brace_stack = []
    functions = []
    linecount = 0

    start_lib_int = False
    linn = 973
    func_index = 0
    for i, line in enumerate(lines):
        linecount += 1

        if (
            line.strip().startswith("library")
            or line.strip().startswith("interface")
            or line.strip().startswith("contract")
        ):
            start_lib_int = True
            brace_stack = []

        if line.strip().startswith("function") or "function" in line.strip():
            inside_function = True
            func_index = i
            start_line = i
            start_of_func = start_line

        if inside_function and "{" in line:
            brace_stack.append("{")

        if not inside_function and i == 0 and vulnerable_line:
            reverse_key = vulnerable_line - 1
            while True:
                if solidity_code[reverse_key].strip().startswith("function"):
                    inside_function = True
                    start_line = reverse_key  # - 1 #i - 1
                    if "{" in solidity_code[reverse_key]:
                        brace_stack.append("{")
                    break
                # if this line is not part of a function and just a contract variable
                elif solidity_code[reverse_key].strip().startswith("contract"):
                    inside_function = False
                    start_line = vulnerable_line
                    print(f"starts with contract {start_line}", line)
                    break
                else:
                    reverse_key -= 1

        if (
            not inside_function
            and (line.strip().startswith("}") or line.strip().endswith("}"))
            and len(brace_stack) > 0
            and start_lib_int
        ):
            brace_stack.pop()
            start_lib_int = False

        # Some incorrectly formatted strings e.g. } function log() {
        if inside_function and (
            line.strip().endswith("}") or re.search(r"^\s+\} function .*$", line)
        ):
            if brace_stack:
                brace_stack.pop()

            # if brace stack is empty means we reached at the end of the function
            if not brace_stack:
                inside_function = False
                end_line = i
                function_code = "".join(solidity_code[start_line : end_line + 1])
                functions_dict = {
                    "source": source,
                    "function_index": func_index,
                    "function_code": function_code,
                    "vulnerability_label": None,
                }
                functions.append(functions_dict)
    df = pd.DataFrame(functions)
    return df
