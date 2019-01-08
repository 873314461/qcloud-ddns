FROM python:3.7.2-alpine3.8

WORKDIR /qcloud-ddns

COPY main.py requirements.txt ./

COPY config.yml /etc/qcloud-ddns/config.yml

VOLUME qcloud-ddns.log

RUN pip install -r requirements.txt --no-cache-dir \
    && rm requirements.txt \
    && sed -i "s/'config.yml'/'\/etc\/qcloud-ddns\/config.yml'/g" main.py

CMD ["python", "main.py"]
