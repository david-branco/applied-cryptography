#!/bin/bash
# Guiao 1 - Alinea 2 - RC4
# Start the class Main_rc4
# example of execution: -genkey key.bin

read option

for cmd in $option
do
	if [ -z "$cmds" ]
	then
		cmds+=$cmd	  	
	else
		cmds+=" "$cmd	
	fi
done

java -jar ../jars/RC4.jar $cmds
