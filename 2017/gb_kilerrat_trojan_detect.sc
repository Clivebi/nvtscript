if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140235" );
	script_version( "2020-08-26T13:46:49+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-26 13:46:49 +0000 (Wed, 26 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-04-05 15:14:52 +0200 (Wed, 05 Apr 2017)" );
	script_name( "KilerRat Trojan Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Malware" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 6666 );
	script_tag( name: "summary", value: "The remote host seems to be infected by the KilerRat remote access trojan." );
	script_tag( name: "vuldetect", value: "Check the response on port 6666." );
	script_tag( name: "solution", value: "A whole cleanup of the infected system is recommended." );
	script_xref( name: "URL", value: "https://www.alienvault.com/blogs/labs-research/kilerrat-taking-over-where-njrat-remote-access-trojan-left-off" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("socket_func.inc.sc");
port = 6666;
if(!get_port_state( port )){
	exit( 0 );
}
vt_strings = get_vt_strings();
data = "0|Kiler|" + vt_strings["default"] + "|Kiler|" + vt_strings["default"] + "|Kiler[endof]";
buf = socket_send_recv( port: port, data: data, length: 64 );
if(!buf || !strlen( buf ) > 0){
	exit( 0 );
}
if(IsMatchRegexp( buf, "^ACK" ) + data + "$"){
	security_message( port: port, data: "The KilerRat trojan seems to be running at this port.\n\nResponse:\n\n" + buf );
	exit( 0 );
}
exit( 0 );

