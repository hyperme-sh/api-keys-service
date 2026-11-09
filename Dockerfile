FROM python:3.13-bookworm@sha256:cc55e4ded9c95f6ce2133b3d096db43f214d280c2a8af65d83e246c8fa7d168c AS install
COPY wheelhouse/ /wheelhouse/
COPY *.whl /candidate/
RUN python -m venv /opt/runtime && /opt/runtime/bin/pip install --no-cache-dir --no-index --no-deps /wheelhouse/*.whl && /opt/runtime/bin/pip install --no-deps /candidate/*.whl && /opt/runtime/bin/pip check

FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72
COPY --from=install /opt/runtime /opt/runtime
COPY tested-dist.zip /qualified/tested-dist.zip
LABEL org.opencontainers.image.source="https://github.com/hyperme-sh/api-keys-service"
ENV PATH=/opt/runtime/bin:$PATH
USER 65532:65532
ENTRYPOINT ["python", "-Im", "api_keys_service.main"]
