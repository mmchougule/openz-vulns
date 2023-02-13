"""
This is a boilerplate pipeline
generated using Kedro 0.18.4
"""
from functools import partial

from kedro.pipeline import Pipeline, node, pipeline

from .de_nodes import get_sanctuary_functions, get_vulnerable_blocks, validate_datasets
from .ds_nodes import train_model, evaluate_model


def create_pipeline(**kwargs) -> Pipeline:
    return pipeline(
        [
            node(
                func=get_vulnerable_blocks,
                inputs="parameters",
                outputs="smartbug_functions_df",
                name="get_vulnerable_functions",
            ),
            node(
                func=get_sanctuary_functions,
                inputs="parameters",
                outputs="sanctuary_functions_df",
                name="get_sanctuary_functions",
            ),
            node(
                func=validate_datasets,
                inputs=["smartbug_functions_df", "parameters"],
                outputs=None,
                name="validate_smartbugs_datasets",
            ),
            node(
                func=validate_datasets,
                inputs=["sanctuary_functions_df", "parameters"],
                outputs=None,
                name="validate_sanctuary_datasets",
            ),
            node(
                func=train_model,
                inputs=["smartbug_functions_df", "parameters"],
                outputs=["lr_model", "x_test", "y_test"],
                name="train_model",
            ),
            node(
                func=evaluate_model,
                inputs=["lr_model", "x_test", "y_test", "parameters"],
                outputs=None,
                name="evaluate_model",
            ),
        ]
    )
