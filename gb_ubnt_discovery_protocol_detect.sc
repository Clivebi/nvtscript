if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106716" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-04-03 09:45:47 +0700 (Mon, 03 Apr 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "UBNT Discovery Protocol Detection" );
	script_tag( name: "summary", value: "UBNT (Ubiquiti Networks) discovery protocol is running on UDP port 10001 at
this host." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_require_udp_ports( 10001 );
	exit( 0 );
}
require("byte_func.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = 10001;
if(!get_udp_port_state( port )){
	exit( 0 );
}
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
query = raw_string( 0x01, 0x00, 0x00, 0x00 );
send( socket: soc, data: query );
recv = recv( socket: soc, length: 4 );
if(strlen( recv ) < 4 || hexstr( recv[0] ) != "01" || hexstr( recv[1] ) != "00" || hexstr( recv[2] ) != "00"){
	close( soc );
	exit( 0 );
}
len = ord( recv[3] );
recv = recv( socket: soc, length: len + 4 );
close( soc );
i = 4;
alt_ip = make_list();
ip = NULL;
for(;i < len;){
	field_type = hexstr( recv[i] );
	i++;
	field_len = getword( blob: recv, pos: i );
	field_data = substr( recv, i + 2, i + 1 + field_len );
	if(field_type == "01" && field_len == 6){
		mac = hexstr( field_data[0] ) + ":" + hexstr( field_data[1] ) + ":" + hexstr( field_data[2] ) + ":" + hexstr( field_data[3] ) + ":" + hexstr( field_data[4] ) + ":" + hexstr( field_data[5] );
	}
	if( field_type == "02" && field_len == 10 ){
		if( ip ){
			alt_ip[max_index( alt_ip )] = ord( field_data[6] ) + "." + ord( field_data[7] ) + "." + ord( field_data[8] ) + "." + ord( field_data[9] );
		}
		else {
			ip = ord( field_data[6] ) + "." + ord( field_data[7] ) + "." + ord( field_data[8] ) + "." + ord( field_data[9] );
		}
	}
	else {
		if( field_type == "03" ){
			firmware = field_data;
			set_kb_item( name: "ubnt_discovery_proto/firmware", value: firmware );
		}
		else {
			if( field_type == "0b" ) {
				host_name = field_data;
			}
			else {
				if( field_type == "0c" ){
					model_short = field_data;
					set_kb_item( name: "ubnt_discovery_proto/short_model", value: model_short );
				}
				else {
					if( field_type == "0d" ) {
						essid = field_data;
					}
					else {
						if(field_type == "14"){
							model_full = field_data;
							set_kb_item( name: "ubnt_discovery_proto/full_model", value: model_full );
						}
					}
				}
			}
		}
	}
	i += field_len + 2;
}
set_kb_item( name: "ubnt_discovery_proto/detected", value: TRUE );
service_register( port: port, ipproto: "udp", proto: "ubnt_discovery" );
report = "Ubiquiti Networks Discovery service is running on this port.\n\nThe following information was extracted:\n\n";
if(ip){
	report += "IP Address:       " + ip + "\n";
}
if(mac){
	report += "MAC Address:      " + mac + "\n";
	register_host_detail( name: "MAC", value: mac, desc: "UBNT Discovery Protocol Detection" );
	replace_kb_item( name: "Host/mac_address", value: mac );
}
if(max_index( alt_ip ) > 0){
	for aip in alt_ip {
		report += "Alternate IP:     " + aip + "\n";
	}
}
if( model_full ) {
	report += "Model:            " + model_full + "\n";
}
else {
	if(model_short){
		report += "Model:            " + model_short + "\n";
	}
}
if(firmware){
	report += "Firmware:         " + firmware + "\n";
}
if(host_name){
	report += "Hostname:         " + host_name + "\n";
	set_kb_item( name: "ubnt_discovery_proto/hostname/detected", value: TRUE );
	set_kb_item( name: "ubnt_discovery_proto/" + port + "/hostname/detected", value: host_name );
}
if(essid){
	report += "ESSID:            " + essid + "\n";
}
log_message( data: report, port: port, proto: "udp" );
exit( 0 );

