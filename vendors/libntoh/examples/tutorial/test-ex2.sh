gcc example2.c -o example2 -Wall -lpcap $(pkg-config ntoh --cflags --libs);
sudo ./example2 -i eth0 -F "tcp";