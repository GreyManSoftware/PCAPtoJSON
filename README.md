# PCAPtoJSON

Well, I wonder what this program might do!

It takes a PCAP file and will print the key headers of the IP + TCP/UDP headers. Anything else is binned, although that would be easy to add in.

You need libpcap to compile against. Compiling is done as follows:

gcc pcaptojson -o pcaptojson -lpcap

run as follows:

./pcaptojson -r <inputfile>

cat packets | ./pcaptojson

Hope this is useful. Feel free to do whatever you want with this software. A mention is always nice :)
