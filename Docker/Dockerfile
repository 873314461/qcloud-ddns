FROM python:3.7.2-alpine3.8

ENV QCLOUD_DDNS_VERSION 1.3

WORKDIR /qcloud-ddns

COPY main.py requirements.txt ./

COPY config.yml /etc/qcloud-ddns/config.yml

VOLUME qcloud-ddns.log

RUN apk update \
    && apk add --no-cache tzdata\
    && ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && pip install -r requirements.txt --no-cache-dir \
    && rm requirements.txt \
    && sed -i "s/'config.yml'/'\/etc\/qcloud-ddns\/config.yml'/g" main.py

ENV TZ=Asia/Shanghai

CMD ["python", "main.py"]

