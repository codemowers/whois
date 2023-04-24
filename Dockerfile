FROM ubuntu
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -yqq python3-pip git
RUN pip3 install sanic cachetools python-whois \
  git+https://github.com/laurivosandi/sanic-prometheus
LABEL name="codemowers/whois" \
      version="rc" \
      maintainer="Lauri Võsandi <lauri@codemowers.io>"
ENV PYTHONUNBUFFERED=1
ADD app /app
ENTRYPOINT /app/app.py
