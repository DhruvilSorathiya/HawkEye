FROM alpine:3.12.4 AS build
ARG REQUIREMENTS=requirements.txt
RUN apk add --no-cache gcc git curl python3 python3-dev py3-pip swig tinyxml-dev \
 python3-dev musl-dev openssl-dev libffi-dev libxslt-dev libxml2-dev jpeg-dev \
 openjpeg-dev zlib-dev cargo rust
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin":$PATH
COPY $REQUIREMENTS requirements.txt ./
RUN ls
RUN echo "$REQUIREMENTS"
RUN pip3 install -U pip
RUN pip3 install -r "$REQUIREMENTS"



FROM alpine:3.13.0
WORKDIR /home/hawkeye

# Place database and logs outside installation directory
ENV SPIDERFOOT_DATA /var/lib/hawkeye
ENV SPIDERFOOT_LOGS /var/lib/hawkeye/log
ENV SPIDERFOOT_CACHE /var/lib/hawkeye/cache

# Run everything as one command so that only one layer is created
RUN apk --update --no-cache add python3 musl openssl libxslt tinyxml libxml2 jpeg zlib openjpeg \
    && addgroup hawkeye \
    && adduser -G hawkeye -h /home/hawkeye -s /sbin/nologin \
               -g "HawkEye User" -D hawkeye \
    && rm -rf /var/cache/apk/* \
    && rm -rf /lib/apk/db \
    && rm -rf /root/.cache \
    && mkdir -p $SPIDERFOOT_DATA || true \
    && mkdir -p $SPIDERFOOT_LOGS || true \
    && mkdir -p $SPIDERFOOT_CACHE || true \
    && chown hawkeye:hawkeye $SPIDERFOOT_DATA \
    && chown hawkeye:hawkeye $SPIDERFOOT_LOGS \
    && chown hawkeye:hawkeye $SPIDERFOOT_CACHE

COPY . .
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

USER hawkeye

EXPOSE 5001

# Run the application.
ENTRYPOINT ["/opt/venv/bin/python"]
CMD ["he.py", "-l", "0.0.0.0:5001"]
