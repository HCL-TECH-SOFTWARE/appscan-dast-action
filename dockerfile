FROM registry.access.redhat.com/ubi8/ubi-minimal:latest
LABEL description="AppScan Presence in Dockerfile for Linux Image"
Write-Host "Inside docker file"
RUN echo "Inside dockerfile"
RUN microdnf update && \
    microdnf install unzip && \
    microdnf clean all
COPY presence.zip /root
RUN mkdir /root/presence/ && unzip /root/presence.zip -d /root/presence/
RUN chmod +x /root/presence/startPresence.sh
ENTRYPOINT  ["/root/presence/startPresence.sh"]

