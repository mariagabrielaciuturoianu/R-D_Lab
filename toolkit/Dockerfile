# Hunt toolkit image: sigma-cli with the OpenSearch backend, and PyMISP.
# Built, scanned, SBOM'd and signed by .github/workflows/ci.yml (R-15, R-17).
# python:3.13-alpine, pinned by multi-arch index digest; Dependabot bumps it.
FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e

# No secrets, keys or certificates ever enter this image; they are mounted at run time.
# pip is removed after the install: it is not needed at run time, and its vendored
# urllib3/msgpack copies were the only HIGH findings in the image (R-17).
WORKDIR /work
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt \
 && pip uninstall --yes pip \
 && adduser -D -H -u 10001 hunter

USER hunter
ENTRYPOINT ["sigma"]
CMD ["--help"]
