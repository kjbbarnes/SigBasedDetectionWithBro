module Mqtt;

export {
	redef ignore_checksums = T;
	redef enum Notice::Type += { Mqtt::Subscribe };
	redef enum Log::ID += { LOG };
	type Info: record {
		ts: time &log;
		src_ip: addr &log;
		src_port: port &log;
		dst_ip: addr &log;
		dst_port: port &log;
		length: count &log;
		payload: string &log;
	};
}

function raise_subscribe_alert (c: connection) {
	NOTICE([ $note = Mqtt::Subscribe, $msg = fmt("%s attempts to subscribe to all topics", c$id$orig_h)]);
}

#Gets the length in bytes of the next MQTT message
function get_next_msg_len (msg: string): count {
	local len = bytestring_to_count(hexstr_to_bytestring(sub_bytes(msg, 3, 2)));
	len = (len + 2) * 2;
	return len;
}

#Gets a single message out of the packet contents
function get_single_message (fullMessage: string, len: count): string {
	local msg = sub_bytes(fullMessage, 1, len);
	return msg;
}

#Removes the already checked message from the full message so that the next message may be processed
function trim_full_message (fullMsg: string, msgToTrim: string): string {
	local msg = subst_string(fullMsg, msgToTrim, "");
	return msg;
}

#Extracts the topic from the single message
function get_topic (msg: string): string {
        local topic = hexstr_to_bytestring(sub_bytes(msg, 13, get_next_msg_len(msg) - 14));
        return topic;
}

#Writes to the mqtt.log whenever mqtt traffic occurs
function write_to_mqtt_log (c: connection, topic: string) {
        local rec: Mqtt::Info = [
                $ts = network_time(),
                $src_ip = c$id$orig_h,
                $src_port = c$id$orig_p,
                $dst_ip = c$id$resp_h,
                $dst_port = c$id$resp_p,
                $length = 0,
                $payload = topic];
        Log::write(Mqtt::LOG, rec);
}

#Checks a message for a subscribe to all request and returns 1 or 0
#A return of 1 will raise a NOTICE
function check_msg_subscribe_all (msg: string, c: connection): bool {
	if (sub_bytes(msg, 1, 2) == "82") {
		local topic = get_topic(msg);
		write_to_mqtt_log(c, topic);
		if ("#" in topic) {
			return T;
		}
	}
	return F;
}

event packet_contents(c: connection, contents: string) {
        if (c$id$resp_p == 1883/tcp) {
                local nextMsgLen: count;
                local singleMessage: string;
                local trimmedMessage: string;
                local fullMessage = string_to_ascii_hex(contents);
                while (fullMessage != "") {
                        nextMsgLen = get_next_msg_len(fullMessage);
                        singleMessage = get_single_message(fullMessage, nextMsgLen);
                        fullMessage = trim_full_message(fullMessage, singleMessage);
                        if (check_msg_subscribe_all(singleMessage, c)) {
				raise_subscribe_alert(c);
			}
                }
        }
}

#Create a log stream upon bro initialization
event bro_init() &priority=5 {
  Log::create_stream(Mqtt::LOG, [$columns=Info, $path="mqtt"]);
}
