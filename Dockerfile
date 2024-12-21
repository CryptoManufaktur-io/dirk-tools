FROM python:3.9.10-bullseye as builder

RUN python --version

RUN curl -sSL https://install.python-poetry.org | python -

ENV PATH="/root/.local/bin:$PATH"

WORKDIR /app

COPY . .

RUN poetry install

RUN ./build.sh

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y ca-certificates bash tzdata hwloc libhwloc-dev wget

COPY --from=builder /app/build/dirk-tools/dirk-tools /usr/local/bin/

RUN mkdir /var/lib/dirk-tools && chmod 0777 /var/lib/dirk-tools

ENTRYPOINT [ "/usr/local/bin/dirk-tools" ]
