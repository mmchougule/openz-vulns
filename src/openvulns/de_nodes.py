"""
Kedro nodes for the data processing pipeline
"""

import logging
import pandas as pd
import re
import os

# Tasks for Q1.
# 1. Node to extract smart contract functions with vulnerability labeled
# 2. Node to extract smart contract functions for all functions in the sanctuary repo

# Node: Read from repo.
# Node: Extract all functions from the repo.


def extract_smartbugs_functions(solidity_code, start_line=None):
    lines = solidity_code[start_line:] if start_line else solidity_code
    inside_function = False
    function_line_number = 0
    function_signature = None
    code_block = ""

    opening_bracket = 0
    closing_bracket = 0
    end_block_line = 0
    start_block_line = 0

    for i, line in enumerate(lines):
        if line.strip().startswith("function"):
            inside_function = True
            function_line_number = i + 1
            function_signature = re.search(r"function.*\(.*\)?", line).group()

        if inside_function and "{" in line:
            opening_bracket += 1

        if line.strip().endswith("}"):
            # when { == } then we break
            closing_bracket += 1

        # print(f"i, {i} {opening_bracket}")
        if not inside_function and i == 0 and start_line:
            reverse_key = start_line - 1
            while True:
                if solidity_code[reverse_key].strip().startswith("function"):
                    inside_function = True
                    function_line_number = reverse_key  # - 1 #i - 1
                    if "{" in solidity_code[reverse_key]:
                        opening_bracket += 1
                        end_line = start_line
                    break
                # if this line is not part of a function and just a contract variable
                elif solidity_code[reverse_key].strip().startswith("contract"):
                    inside_function = False
                    function_line_number = start_line
                    print(f"starts with contract {function_line_number}", line)
                    break
                else:
                    reverse_key -= 1

        if function_line_number and opening_bracket == closing_bracket:
            inside_function = False
            start_block_line = int(function_line_number)
            end_block_line = i + 1 if not start_line else start_line + i + 1
            code_block = "".join(solidity_code[start_block_line : end_block_line + 1])

        if end_block_line > start_block_line and not inside_function:
            # break to get out of the loop
            break
    return code_block


def get_additional_features(solidity_code):
    """
    Get additional features from the solidity code
    :param solidity_code:
    :return:
    """
    use_of_libraries = 0
    if "import" in "".join(solidity_code):
        use_of_libraries = 1

    # Access Control
    access_control = 0
    if "require" in "".join(solidity_code) or "require(" in solidity_code:
        access_control = 1

    # Arithmetic Operations
    num_arithmetic_ops = len(re.findall(r"\+|\-|\*|\/", solidity_code))

    # Use of Pragma Directives
    pragma_directives = 0
    if "pragma" in solidity_code:
        pragma_directives = 1

    # Use of Design Patterns
    use_of_design_patterns = 0
    if (
        "inheritance" in solidity_code
        or "state machine" in solidity_code
        or "delegate" in solidity_code
    ):
        use_of_design_patterns = 1
    return [
        use_of_libraries,
        access_control,
        num_arithmetic_ops,
        pragma_directives,
        use_of_design_patterns,
    ]


def get_vulnerable_blocks(parameters):
    """
    Iterate through all files in the repo and extract all functions with vulnerability
    label mentioned in the comments.
    :param parameters: Parameters conf file
    :return: Pandas dataframe with all functions with vulnerability label
    """
    logger = logging.getLogger(__name__)

    repo_dir = parameters["repo_dir"]
    repo_url = parameters["repo_url"]
    code_blocks = []
    for root, dirs, files in os.walk(repo_dir):
        try:
            for file in files:
                with open(os.path.join(root, file), "r") as f:
                    lines = f.readlines()
                    vuln_lines_spec = list(
                        filter(lambda x: re.search("@vulnerable_at_lines", x), lines)
                    )
                    # get all of them when vulnerable lines are not mentioned
                    if not vuln_lines_spec:
                        continue
                    vuln_lines_str = (
                        vuln_lines_spec[0].split(":")[-1].strip().split(",")
                    )

                    is_in_seq = False
                    vuln_lines = list(map(lambda x: int(x), vuln_lines_str))

                    if (
                        1
                        < len(vuln_lines)
                        == int(vuln_lines[-1]) - int(vuln_lines[0]) + 1
                    ):
                        is_in_seq = True

                    (
                        use_of_libraries,
                        access_control,
                        num_arithmetic_ops,
                        pragma_directives,
                        use_of_design_patterns,
                    ) = get_additional_features("".join(lines))

                    for v in vuln_lines:
                        start_line = int(v) - 1
                        end_line = start_line
                        vul_label = re.sub(
                            # PEP 8: W605 invalid escape sequence '\s'
                            r"// <yes> <report>\s|\n|\t",
                            "",
                            lines[start_line - 1],
                        ).strip()
                        code_block = extract_smartbugs_functions(lines, start_line)
                        code_dict = {
                            "source": os.path.join(root, file).replace(
                                repo_dir, repo_url
                            ),
                            "function_index": v,
                            "function_code": code_block,
                            "vulnerability_label": vul_label,
                            "use_of_libraries": use_of_libraries,
                            "use_of_design_patterns": use_of_design_patterns,
                            "pragma_directives": pragma_directives,
                            "access_control": access_control,
                            "num_arithmetic_ops": num_arithmetic_ops,
                        }
                        code_blocks.append(code_dict)
                        if is_in_seq:
                            break
        except Exception as e:
            logger.error(f"Error in get_vulnerable_blocks: {e}")
            continue

    codes_df = pd.DataFrame(code_blocks)
    logger.info(f"Total number of vulnerable code blocks: {codes_df.shape}")
    return codes_df


def extract_sanctuary_functions(lines, source):
    inside_function = False
    start_line = 0
    # Initialize a stack to keep track of opening and closing braces
    brace_stack = []
    functions = []
    linecount = 0

    start_lib_int = False
    linn = 973
    func_index = 0

    (
        use_of_libraries,
        access_control,
        num_arithmetic_ops,
        pragma_directives,
        use_of_design_patterns,
    ) = get_additional_features("".join(lines))

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

        if inside_function and "{" in line:
            brace_stack.append("{")

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
                function_code = "".join(lines[start_line : end_line + 1])
                functions_dict = {
                    "source": source,
                    "function_index": func_index,
                    "function_code": function_code,
                    "vulnerability_label": None,
                    "use_of_libraries": use_of_libraries,
                    "use_of_design_patterns": use_of_design_patterns,
                    "pragma_directives": pragma_directives,
                    "access_control": access_control,
                    "num_arithmetic_ops": num_arithmetic_ops,
                }
                functions.append(functions_dict)
    df = pd.DataFrame(functions)
    return df


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


def validate_datasets(df, parameters):
    """
    Validate the dataset generated by the feature layer
    :param df:
    :param parameters:
    :return:
    """
    print(df.head())
    print(df.columns)
    function_cols = parameters.get("function_cols")
    logging.info(f"vulnerable labels: {df['vulnerability_label'].value_counts()}")
    assert df.shape[0] > 0, "No data in the dataset"
    assert df.columns.tolist() == function_cols, "Columns do not match"
    logging.info(f"Validated dataset with {df.shape[0]} rows")
