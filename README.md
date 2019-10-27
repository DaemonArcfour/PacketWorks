## PWv1.0
![Command line](http://0x0.st/zYT0.png)

|Command| Description|
|--|--|
|open_script|*Opens a script to read commands from (commands are separated by a line break)*|
|init_raw_udp|*Creates a raw UDP packet template*|
|init_raw_tcp|*Creates a raw TCP packet template*|
|set_packet_data|*Reads binary data into a raw packet payload buffer*|
|set_source_ip|*Sets source IP*|
|set_source_port|*Sets source port*|
|set_destination_ip|*Sets destination IP*|
|set_destination_port|*Sets destination port*|
|get_data_dump|*Prints out the payload buffer in hex*|
|get_crafted_packet_dump|*Prints out the current raw packet in hex*|
|select_network_adapter|*Selects a network adapter to use*|
|send_packet|*Send the crafted packet*|
|wait|*Executes "Sleep()" between commands (meant to be used for scripting)*|

**Right now it only fully supports raw UDP packets, I will add the support for raw TCP packets later.**

Latest Npcap needs to be installed to run this.

TO-DO:
 1. Add a command to edit source MAC.
 3. Fix raw TCP packets.
 2. Clean up the code.
 
 **<!> To compile this you'll need Npcap SDK <!>**
