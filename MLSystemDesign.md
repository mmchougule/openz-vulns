## Overview
ML system design for vulnerability detection in smart contracts.

4 major components:

1. Data Ingestion Service
2. Data Transformation Service
3. Machine Learning and Feature Service (Vulnerability Detection)
4. Consumers
5. Observability

To build a production ready ML system, we follow this idea of layers. Data flow happens in layers. This makes it composable for engineers to build modular pipelines of data and plug in as needed. This ML system will continuously ingests data, processes, transforms, and trains models. We use a library called kedro for building data pipelines, it includes a starter pack that follows software engineering as well as data flow best  practices. Kedro is used to compose modular pipelines that can be executed one of basis as needed or as a part of a pipeline.

## Systems Architecture

Vulnerability Detection Architecture
![openzeppelin_vuln_detection_v1.jpg](docs%2Fimages%2Fopenzeppelin_vuln_detection_v1.jpg)

Long Term ML Systems Architecture
![openzeppelin_v2.jpg](docs%2Fimages%2Fopenzeppelin_v2.jpg)

For the purposes of the current problem, we will build a kedro pipeline that follows this flow:

## Steps:
```
Data ingestion
  -> save to S3/storage layer
    -> Cleanup, data type checks, and validate quality of the data
      -> Build features that are as granular as the unit of analysis, like, function code, num_lines, 
        -> Build transaction features for trending topic
          -> Build search features
            -> Take the model input parquet file built in the previous step, validate the data
              -> Train the model, track experiments, log, model performance
              -> deploy model to model registry or an accessible location once validated
            -> Feature DB layer will be a postgres DB where we can store tx trending results, functions codes database
              -> encode functions code blocks into a vector database like qdrant for semantic search engine
              -> Serve model output and feature db output through
                -> GraphQL API, connect with hasura to give GraphQL access to the end users
                -> REST API, in python or node that queries postgres db for the given use cases
                  -> API integration in the forta app and other API consumers
```
We will then containerize this solution, kedro comes with a docker plugin. Using, kedro docker build and push, we can deploy this solution on an orchestrator in the cloud (aws batch/gcp cloud run jobs/etc.). 

Schedule the docker run with specific commands to run once an hour or an agreed time range

Monitor the ML system using an out of box tool, or open source Prometheus (metrics monitoring), Grafana (metrics visualizations), Loki (logging), and CircleCI (CI/CD).

Next steps:
1. Add data distribution drift detection
2. Add feature distribution drift detection
3. Add model bias distribution drift detection
4. Add model performance distribution drift detection
5. AB testing models
6. Feature stores so we can reuse features for new models
7. Enhance model validation service