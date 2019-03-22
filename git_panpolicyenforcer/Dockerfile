FROM alpine:3.8
RUN apk --no-cache add ca-certificates
WORKDIR /bin/
COPY bin/panpolicyenforcer .
WORKDIR /home/
COPY panpolicyenforcer/license.txt . 
ENTRYPOINT [ "/bin/panpolicyenforcer" ]
CMD [ "9693" ]
EXPOSE 9693 
