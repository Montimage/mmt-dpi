# Install mmt-sdk in cubieboard X in a micro-SD card

[Install cubieboard](https://github.com/cubieplayer/Cubian/wiki/Install-Cubian)

# Install mmt-sdk

* Download mmt-sdk-0.1-cubieboard.zip

* Extract .zip file

* Install some required packages:

```sh
sudo apt-get install -y build-essential make gcc libpcap-dev libpth-dev libxml2-dev
```

* Install mmt-sdk

```sh
cd mmt-sdk-0.1-cubieboard/
sudo make install
```

* Test mmt-sdk

There are some examples with mmt-sdk

```sh
cd mmt-sdk-0.1-cubieboard/examples
gcc -o extract extract_all.c -lmmt_core -ldl -lpcap -lpthread
sudo ./extract -i eth0
```

That's it!
