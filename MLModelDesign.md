## Overview
ML system design for vulnerability detection in smart contracts.

Components:

1. Data Ingestion Service
2. Data Transformation Service
3. Machine Learning and Feature Service (Vulnerability Detection)
4. Consumers
5. Observability

## Steps:

1. Data ingestion:
    - Get data for smart contract functions, audit reports, vulnerable labels, transactions
    - Save to S3/storage layer
    - Cleanup, data type checks, and validate quality of the data
2. Exploratory Data Analysis and Data Transformation:
    - Explore the data, look for patterns, and build hypothesis
    - Decide on what the unit of analysis is. It could be function code, num_lines, occurrence of a function, etc.
    - Build features that are at the level of the unit of analysis
    - Build transaction features for trending topic
    - Build search features
3. Model Input table:
    - Use features built above to build a model input table by joining the features with the labels 
    - Save this dataframe in parquet format on our storage layer
    - Validate the model input dataset
4. Model Training and Validation:
    - Think through the modeling techniques, identify if we need to use a supervised or unsupervised model
    - Perform EDA on the smart contract and cluster similar ones together to potentially use unsupervised learning
    - Could label manually from the clustering output and verify and use supervised learning
    - Train a classifier model, track experiments, log, model performance
    - deploy model to model registry or an accessible location once validated
5. Model Serving:
    - Serve model output and feature db output through
        - GraphQL API, connect with hasura to give GraphQL access to the end users
        - REST API, in python or node that queries postgres db for the given use cases
            - API integration in the forta app and other API consumers
6. Feature DB layer:
    - Feature DB layer will be a postgres DB where we can store tx trending results
    - functions code blocks database for semantic search engine


## Modeling Techniques:

Models to try for classification:
- Logistic Regression
- Random Forest
- XGBoost

Vectorizer:
- Use TfidfVectorizer to convert smart contract code text into vectors.
  - This will be used to build a semantic search engine for smart contract code blocks
  - This will also be used as inputs to the Logistic Regression model


Models to try for clustering:
- KMeans
- DBSCAN

Feature ideas:

(try features and see which ones are useful from feature importance)

Function contract features:
- function code vectorizer
- num_lines
- occurrence of a function
- num functions
- use of libraries and APIs
- use of external contracts
- access control: roles or permissions 0 or 1
- num arithmetic operations
- num external calls

Function code quality features:
- use of pragma
- use of design patterns (e.g. factory pattern)
- use of inheritance

Transaction contract features (potentially):
- num transactions
- num unique addresses
- size of transaction
- volume eth transferred

Audit report features:
- num audit reports



## Architecture:

Storage:
- S3/storage layer
- Postgres
- Qdrant

Processing:
- Kedro
- Docker
- AWS Batch/GCP Cloud Run Jobs
- Prometheus

API:
- GraphQL
- REST

Authentication:
- web3auth
- JWT

Model Registry:
- MLFlow

Model Serving:
- FastAPI
- Uvicorn
