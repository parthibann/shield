FROM python:3.11-slim
ADD . /code
WORKDIR /code
RUN pip install -r requirements.txt
CMD python ./bin/shield
