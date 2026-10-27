# syntax=docker/dockerfile:1.7
# wallfacer/inference — llama.cpp server on Vulkan (CMP-01, CMP-02, CMP-09, PRV-05, WF-02).
# No CUDA. AMD runs on Mesa RADV; NVIDIA needs its Vulkan ICD from the host driver (see README).
ARG BASE_IMAGE=wallfacer/base:latest
ARG DEBIAN_IMAGE=debian:trixie-slim

# ---------- build llama.cpp at a pinned ref ----------
FROM ${DEBIAN_IMAGE} AS build
ARG LLAMA_CPP_REF
RUN test -n "${LLAMA_CPP_REF}" || { echo "set LLAMA_CPP_REF to a llama.cpp release tag, e.g. bNNNN" >&2; exit 1; }
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates git build-essential cmake libvulkan-dev glslc \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch "${LLAMA_CPP_REF}" https://github.com/ggml-org/llama.cpp.git . \
 && cmake -B build \
      -DGGML_VULKAN=ON \
      -DGGML_NATIVE=OFF \
      -DLLAMA_CURL=OFF \
      -DBUILD_SHARED_LIBS=OFF \
      -DLLAMA_BUILD_TESTS=OFF \
      -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build -j"$(nproc)" --target llama-server \
 && install -D build/bin/llama-server /out/llama-server

# ---------- runtime ----------
FROM ${BASE_IMAGE}
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends libvulkan1 mesa-vulkan-drivers libgomp1 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/llama-server /usr/local/bin/llama-server
COPY inference-entrypoint.sh /usr/local/bin/inference-entrypoint.sh
RUN chmod 0755 /usr/local/bin/inference-entrypoint.sh

# GPU access comes from the render group of the host; compose adds it via group_add.
USER wf
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/inference-entrypoint.sh"]
