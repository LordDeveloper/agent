# Portable glibc binary (Debian/Ubuntu/CentOS/RHEL/Fedora, etc.)
# Build with: docker build --platform linux/amd64|linux/arm64 --target export ...
FROM python:3.12-slim-bookworm AS build

WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends binutils \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir --prefer-binary -r requirements.txt pyinstaller

COPY src ./src
COPY agent.spec ./
RUN pip install --no-cache-dir -e . \
    && pyinstaller --clean --noconfirm agent.spec

FROM scratch AS export
COPY --from=build /src/dist/agent /agent
