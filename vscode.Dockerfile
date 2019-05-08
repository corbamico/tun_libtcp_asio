FROM buildpack-deps:disco

RUN apt-get update && apt-get install  -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    --no-install-recommends
RUN curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg ; \
    install -o root -g root -m 644 microsoft.gpg /etc/apt/trusted.gpg.d/  ; \
    echo "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main" > /etc/apt/sources.list.d/vscode.list ; 
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libasio-dev \
    libtins-dev \
    netcat \
    tshark \
    cmake \
    libasound2 \
    git \
    libatk1.0-0 \
    libcairo2 \
    libexpat1 \
    libfontconfig1 \
    libfreetype6 \
    libgtk2.0-0 \
    libpango-1.0-0 \
    libxrandr2 \
    libxrender1 \
    libx11-xcb1 \
    libxcursor1 \
    libxcomposite1 \
    libxi6 \
    libxext6 \
    libxfixes3 \
    libxss1 \
    libxtst6 \
    iproute2 \
    fish \
    --no-install-recommends
RUN apt-get update && apt-get install -y code --no-install-recommends; \
    rm -rf /var/lib/apt/lists

RUN code --user-data-dir /var/run/code --force \
    --install-extension ms-vscode.cpptools  \
    --install-extension pkief.material-icon-theme \
    --install-extension vector-of-bool.cmake-tools \
    --install-extension twxs.cmake