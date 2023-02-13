# Pipeline

> *Note:* This is a `README.md` boilerplate generated using `Kedro 0.18.4`.

Pre-requisities:
1. Python 3.9 and conda environments
2. Install `kedro` using `pip install kedro`
3. Copy the required repos to a `data/01_raw` folder and update parameters.yml

## Installation

1. Clone the repo
2. Create a conda environment using `conda env create -n name python=3.9`
3. Activate the environment using `conda activate name`
4. pip install -r src/requirements.txt

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


## Pipeline inputs

### `parameters`

|      |                    |
| ---- | ------------------ |
| Type | `dict` |
| Description | Raw data repo configs) |


## Pipeline intermediate outputs

### `X_train`

|      |                    |
| ---- | ------------------ |
| Type | `pandas.DataFrame` |
| Description | DataFrame containing train set features |

### `y_train`

|      |                    |
| ---- | ------------------ |
| Type | `pandas.Series` |
| Description | Series containing train set target. |

### `X_test`

|      |                    |
| ---- | ------------------ |
| Type | `pandas.DataFrame` |
| Description | DataFrame containing test set features |

### `y_test`

|      |                    |
| ---- | ------------------ |
| Type | `pandas.Series` |
| Description | Series containing test set target |

### `y_pred`

|      |                    |
| ---- | ------------------ |
| Type | `pandas.Series` |
| Description | Predictions from the 1-nearest neighbour model |


## Pipeline outputs

### `None`
