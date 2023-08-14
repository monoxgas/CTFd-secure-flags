FROM ctfd/ctfd
COPY . ./CTFd/plugins/CTFd-secure-flags
RUN pip install -r ./CTFd/plugins/CTFd-secure-flags/requirements.txt