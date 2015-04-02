
if [ -z "${BASE}" ]; then
    export BASE="https://localhost"
fi

if [ -z "${MDX}" ]; then
    export MDX="http://localhost/mdx"
fi

if [ -z "${CDB}" ]; then
    export CDB="http://localhost/cdb"
fi

if [ -z "${DISCO}" ]; then
    export DISCO="http://localhost/disco"
fi

#pefim_server.py pefim_proxy_conf

#EXPOSE 8999

