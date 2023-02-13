# Pipeline

## Run

1. `kedro run` - runs all nodes of the pipeline
2. `kedro run -n get_vulnerable_functions` - runs only the `get_vulnerable_functions` node
3. `kedro run -n get_sanctuary_functions` - runs only the `get_sanctuary_functions`

## Overview

This pipeline:
1. Gets repo and data configuration mentioned in `conf/base/parameters.yml`
2. extracts vulnerable functions by line numbers and save as parquet
3. extracts all functions from the sanctuary repo and save as parquet
4. builds a graph of vulnerable functions and save as parquet
5. builds a sample ML model and shows model performance
