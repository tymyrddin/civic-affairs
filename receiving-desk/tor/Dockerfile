FROM alpine:3.20
RUN apk add --no-cache tor \
    && mkdir -p /var/lib/tor/hidden_service \
    && chown -R tor:tor /var/lib/tor \
    && chmod 700 /var/lib/tor /var/lib/tor/hidden_service
COPY torrc /etc/tor/torrc
RUN chown root:tor /etc/tor/torrc && chmod 640 /etc/tor/torrc
USER tor
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
