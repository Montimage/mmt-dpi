gcc example1.c -o example1 -Wall -lpcap $(pkg-config ntoh --cflags --libs);
sudo ./example1 -i eth0;