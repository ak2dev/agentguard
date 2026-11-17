FROM debian:12@sha256:ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12
RUN curl -fsSLo /tmp/tool.tgz https://get.example.invalid/tool-1.2.3.tgz \
 && echo "cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34  /tmp/tool.tgz" | sha256sum -c - \
 && tar -xzf /tmp/tool.tgz -C /opt
USER 1000
