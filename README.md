# summerseed


there are two processes to send and recieve a packet, a header file for struct of message types, and a txt file to store mac and sur/names of connections.

to run recv.c 
	
	
	$ sudo ./recv
to run trans.c
	
	
	$ sudo ./trans [type] [target name] [target surname] [massage if it is necessary]
example: 
	
	
	$ sudo ./trans 3 okan erdogan hello okan

type 0 -> QUERY_BROADCAST
     1 -> QUERY_UNICAST
     2 -> HELLO_RESPONSE
     3 -> CHAT
     4 -> CHAT_ACK
     5 -> EXITING
