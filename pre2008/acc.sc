if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10351" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 183 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-1999-0383" );
	script_name( "The ACC router shows configuration without authentication" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2000 Sebastian Andersson" );
	script_family( "Remote file access" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/banner/available" );
	script_tag( name: "solution", value: "Upgrade the software." );
	script_tag( name: "summary", value: "The remote router is an ACC router.

  Some software versions on this router will allow an attacker to run the SHOW
  command without first providing any authentication to see part of the router's
  configuration." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || ContainsString( banner, "Login:" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(soc){
	first_line = telnet_negotiate( socket: soc );
	if(ContainsString( first_line, "Login:" )){
		req = NASLString( "\\x15SHOW\\r\\n" );
		send( socket: soc, data: req );
		r = recv_line( socket: soc, length: 1024 );
		r = recv_line( socket: soc, length: 1024 );
		if(( ContainsString( r, "SET" ) ) || ( ContainsString( r, "ADD" ) ) || ( ContainsString( r, "RESET" ) )){
			security_message( port );
			for(;!( ContainsString( r, "RESET" ) );){
				if(ContainsString( r, "Type 'Q' to quit" )){
					send( socket: soc, data: "Q" );
					close( soc );
					exit( 0 );
				}
				r = recv( socket: soc, length: 1024 );
			}
		}
	}
	close( soc );
}

