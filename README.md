# SigBasedDetectionWithBro
Signature based detection using Bro scripting. Specifically detect DNS exfiltration/tunneling and suspicious subscribe traffic for MQTT protocol.
```
1. Check if packet is over port 1883
2. Initialize local variables
3. Convert the string to ascii hex code so it's easier to work with (since it is then all numbers, ie 8206 etc)
4. While the full message content is not an empty string do the following
	a. get the length of the next message, which is the 2nd 2 character hex value of the string  (since messages can be stacked in the same packet)
	b. extract the single message
	c. remove the single message from the full message resulting in the remaining messages to parse
	d. check if the message topic contains a # indicating a subscribe all msg
		i. do this by checking the first 2 characters in the hex string are "82"
		ii. then extract the topic and check for the # (hint: the topic always starts at the 13th character in the hex string, and is the full single msg len - 14)
		iii. at this point after extracting the topic, write to the mqtt.log that an mqtt subscribe request was made (if you have functions doing this you will need to pass the connection info)
	e. if the message topic contained a #, then raise an alert for a subscribe all request
    
Builtin Functions used: 
1. string_to_ascii_hex(string)
2. bytestring_to_count(bytestring)
3. hexstr_to_bytestring(hexstring) [hint: the string_to_ascii_hex function returns what is considered a hexstring)]
4. sub_bytes(string, start index, length to grab) [hint: this function {despite the name} is used to grab a substring from a string, not just bytes]
5. subst_string(string,  stringToMatch, replacement)
```
