# The BlueCash mint, built from source in one image.
#
# Two stages, because the backend does not have a pure-Python implementation of
# the protocol maths: it calls the Rust core through PyO3. So the image has to
# compile Rust, and then must not carry the Rust toolchain into production --
# that is the difference between an image of roughly 200 MB and one over 2 GB.
#
# Build and run locally exactly as the host will:
#   docker build -t bluecash-mint .
#   docker run --rm -p 8000:8000 \
#     -e BLUECASH_DATABASE_URL="postgresql+psycopg://user:pass@host/db" bluecash-mint

# --- stage 1: compile the Rust core into a wheel ----------------------------
FROM rust:1.83-slim-bookworm AS crypto

# `python3-dev` provides the headers PyO3 links against; `patchelf` is what
# maturin uses to fix up the shared object's runtime paths.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-dev python3-pip python3-venv patchelf \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --break-system-packages --no-cache-dir maturin==1.15.0

WORKDIR /build
# Manifests first, so a change to the source does not invalidate the cached
# dependency compile -- which is most of the build time.
COPY crates/bluecash-crypto/Cargo.toml crates/bluecash-crypto/Cargo.lock crates/bluecash-crypto/pyproject.toml ./
RUN mkdir -p src && echo "fn main() {}" > src/lib.rs \
    && cargo fetch --locked \
    && rm -rf src

COPY crates/bluecash-crypto/src ./src
COPY crates/bluecash-crypto/tests ./tests

# `offline = true` in pyproject.toml is a convenience for the laptop, where the
# registry is already warm. Here the dependencies were just fetched, so the
# flag only gets in the way.
RUN sed -i 's/^offline = true/offline = false/' pyproject.toml \
    && maturin build --release --features python --out /wheels

# --- stage 2: the runtime ---------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

# Never run the mint as root. It holds the signing keys.
RUN useradd --create-home --uid 10001 mint

WORKDIR /app

# Dependencies before application code: this layer is cached across every
# deploy that does not change requirements.txt.
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY --from=crypto /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

COPY backend/ ./

# Fail now, loudly, rather than on the first request, if the extension did not
# install correctly. A mint that starts without its crypto core is worse than
# one that refuses to start.
RUN python -c "import bluecash_crypto as bc; print('bluecash_crypto', bc.__version__)"

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER mint
EXPOSE 8000

# PORT is set by the host; 8000 is the local default.
ENV PORT=8000 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["docker-entrypoint.sh"]
