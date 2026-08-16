# Build a Linux amd64 one-file binary for VPS deploy.
FROM python:3.12-slim AS build

WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends binutils \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt ./
COPY src ./src
COPY agent.spec ./

RUN pip install --no-cache-dir -r requirements.txt pyinstaller \
    && pip install --no-cache-dir -e . \
    && pyinstaller --clean --noconfirm agent.spec

FROM scratch AS export
COPY --from=build /src/dist/agent /agent
