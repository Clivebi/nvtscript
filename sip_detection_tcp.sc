if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108020" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Detect SIP Compatible Hosts (TCP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Noam Rathaus" );
	script_family( "Service detection" );
	script_dependencies( "find_service5.sc" );
	script_require_ports( "Services/sip", 5060, 5061, 5070 );
	script_xref( name: "URL", value: "http://www.cs.columbia.edu/sip/" );
	script_tag( name: "summary", value: "A Voice Over IP service is listening on the remote port.

  The remote host is running SIP (Session Initiation Protocol), a protocol
  used for Internet conferencing and telephony." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("sip.inc.sc");
require("misc_func.inc.sc");
proto = "tcp";
port = service_get_port( default: 5060, ipproto: proto, proto: "sip" );
banner = sip_get_banner( port: port, proto: proto );
if(!full_banner = get_kb_item( "sip/full_banner/" + proto + "/" + port )){
	exit( 0 );
}
if(banner){
	set_kb_item( name: "sip/banner/available", value: TRUE );
	serverbanner = get_kb_item( "sip/server_banner/" + proto + "/" + port );
	if(serverbanner){
		desc = "Server Banner: " + serverbanner;
	}
	uabanner = get_kb_item( "sip/useragent_banner/" + proto + "/" + port );
	if(uabanner){
		if(desc){
			desc += "\n";
		}
		desc += "User-Agent: " + uabanner;
	}
}
options = get_kb_item( "sip/options_banner/" + proto + "/" + port );
if(options){
	desc += "\nSupported Options: " + options;
}
desc += "\n\nFull banner output:\n\n" + full_banner;
set_kb_item( name: "sip/detected", value: TRUE );
set_kb_item( name: "sip/port_and_proto", value: port + "#-#" + proto );
log_message( port: port, protocol: proto, data: desc );
service_register( port: port, ipproto: proto, proto: "sip", message: "A service supporting the SIP protocol was idendified." );
exit( 0 );

