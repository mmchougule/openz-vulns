"""
Kedro nodes for a sample data science pipeline
"""

import logging
import pandas as pd
import re
import os

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import LabelEncoder


def encode_vulnerable_label(df: pd.DataFrame) -> pd.DataFrame:
    encoder = LabelEncoder()
    encoder.fit(df["vulnerability_label"])
    return encoder.transform(df["vulnerability_label"])


def train_model(df: pd.DataFrame, parameters: dict) -> [LogisticRegression, pd.DataFrame, pd.DataFrame]:
    # Load the data into a pandas dataframe
    vuln_df = df[df["vulnerability_label"].isin(parameters["vulnerable_labels"])]
    vuln_df["vulnerability_label_encoded"] = encode_vulnerable_label(vuln_df)

    # Split the data into training and test sets
    train_df, test_df = train_test_split(vuln_df, test_size=0.2)

    # Convert the function_code column into numerical features using CountVectorizer
    vectorizer = CountVectorizer()
    x_train = vectorizer.fit_transform(train_df['function_code'])
    x_test = vectorizer.transform(test_df['function_code'])

    # Convert the vulnerability_label column into numerical labels
    y_train = train_df['vulnerability_label_encoded']
    y_test = test_df['vulnerability_label_encoded']

    # Train a logistic regression model on the training data
    model = LogisticRegression()
    model.fit(x_train, y_train)

    return [model, x_test, y_test]


def evaluate_model(model: LogisticRegression, x_test: pd.DataFrame, y_test: pd.Series, parameters: dict) -> None:
    """
    Evaluate the model
    :param model: LR Model
    :param x_test: x test
    :param y_test: y test
    :param parameters: parameters
    :return: None
    """
    logger = logging.getLogger(__name__)
    y_pred = model.predict(x_test)

    accepted_accuracy = parameters["accepted_accuracy"]
    # Calculate the accuracy of the model
    accuracy = accuracy_score(y_test, y_pred)
    logger.info(f"accuracy: {accuracy}")
    logger.info(f"Classification report:")
    logger.info(classification_report(y_test, y_pred))
    logger.info(f"Confusion matrix:")
    logger.info(confusion_matrix(y_test, y_pred))

    assert accuracy > accepted_accuracy, "Accuracy is too low"
