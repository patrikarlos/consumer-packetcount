Very simple tool that just counts number of packets and the volume of those counted packets.
Volume is on the LINK level.

Normal filter capabilities applies. Tool DOES not discriminate.

Output
PACKETS:<number of packets matching filter>
VOLUME:<sum of captured sizes, for the matched packets>



Requirements:
build_essentials
libcap_utils

Build:
make clean;
make
make install