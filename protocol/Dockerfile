# The Convo node as an OCI image (§0, Part IV): builds `convo_node` with the
# Swift toolchain, ships it on a slim runtime image. The node listens on 8080
# for HTTP, and, when no TURN service is configured, 3478/udp+tcp for its own
# STUN/TURN with relay sockets on 18100-18199/udp. Persist /var/convo: the
# key, mailbox, log and directory.
#
# Self-hosted:
#   docker build -t convo_node .
#   docker run -p 8080:8080 -p 3478:3478/udp -p 3478:3478 -p 18100-18199:18100-18199/udp \
#     -v convo:/var/convo -e CONVO_PUBLIC_URL=https://node.example convo_node
# Cloud Run: --max-instances 1, a Cloud Storage volume at /var/convo, and
# CLOUDFLARE_TURN_KEY_ID + CLOUDFLARE_TURN_API_TOKEN for TURN.
FROM swift:6.4.2-noble AS build
WORKDIR /src
COPY Package.swift ./
COPY Sources ./Sources
COPY Tests ./Tests
COPY Examples ./Examples
# The Apple-only WebRTC targets pull a package the node never links.
RUN sed -i '/apple-only-begin/,/apple-only-end/d' Package.swift && rm -rf Sources/ConvoWebRTC Sources/ConvoCalling \
 && swift build -c release --product convo_node --static-swift-stdlib

FROM ubuntu:noble
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libcurl4 libxml2 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/.build/release/convo_node /usr/local/bin/convo_node
ENV PORT=8080 CONVO_STATE_DIR=/var/convo
VOLUME ["/var/convo"]
# Relay sockets use 18100-18199/udp as well; registries reject port ranges in
# EXPOSE, so publish them on the run line.
EXPOSE 8080 3478/udp 3478/tcp
HEALTHCHECK CMD ["/bin/sh", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080 && printf 'GET /health HTTP/1.0\\r\\n\\r\\n' >&3 && head -c 200 <&3 | grep -q '\"ok\":true'"]
ENTRYPOINT ["/usr/local/bin/convo_node"]
