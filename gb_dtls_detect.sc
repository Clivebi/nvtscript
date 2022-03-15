if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145817" );
	script_version( "2021-04-28T07:12:47+0000" );
	script_tag( name: "last_modification", value: "2021-04-28 07:12:47 +0000 (Wed, 28 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-23 05:11:18 +0000 (Fri, 23 Apr 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Datagram Transport Layer Security (DTLS) Detection" );
	script_tag( name: "summary", value: "A Datagram Transport Layer Security (DTLS) enabled Service is
  running at this port." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "global_settings.sc", "gb_open_udp_ports.sc" );
	script_require_udp_ports( 443, 601, 853, 2221, 3391, 3478, 4433, 4740, 4755, 5061, 5246, 5247, 5349, 5684, 5868, 6514, 8232, 10161, 10162 );
	exit( 0 );
}
require("byte_func.inc.sc");
require("host_details.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("ssl_funcs.inc.sc");
require("dtls_func.inc.sc");
require("dump.inc.sc");
default_ports = make_list( 443,
	 601,
	 853,
	 2221,
	 3391,
	 3478,
	 4433,
	 4740,
	 4755,
	 5061,
	 5246,
	 5247,
	 5349,
	 5684,
	 5868,
	 6514,
	 8232,
	 10161,
	 10162 );
port_list = unknownservice_get_ports( default_port_list: default_ports, ipproto: "udp" );
for port in port_list {
	if(!get_udp_port_state( port )){
		continue;
	}
	if(service_is_known( port: port, ipproto: "udp" )){
		continue;
	}
	soc = open_sock_udp( port );
	if(!soc){
		continue;
	}
	seq_num = dtls_client_hello( socket: soc );
	if(isnull( seq_num )){
		close( soc );
		continue;
	}
	if(seq_num != -1){
		dtls_send_alert( socket: soc, seq_num: seq_num );
	}
	set_kb_item( name: "dtls/" + port + "/detected", value: TRUE );
	service_register( port: port, proto: "dtls", ipproto: "udp" );
	report = "A DTLS enabled service is running at this port.";
	if(seq_num == -1){
		report += "\n\nThe server responded with an \"Alert\" Message";
		set_kb_item( name: "dtls/" + port + "/alert_received", value: TRUE );
	}
	log_message( port: port, data: report, proto: "udp" );
}
exit( 0 );

