if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15854" );
	script_version( "$Revision: 13011 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-10 09:02:19 +0100 (Thu, 10 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:N" );
	script_xref( name: "OSVDB", value: "3119" );
	script_name( "POP2 Unencrypted Cleartext Login" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 George A. Theall" );
	script_family( "General" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/pop2", 109 );
	script_tag( name: "solution", value: "Encrypt traffic with SSL/TLS using stunnel." );
	script_tag( name: "summary", value: "The remote host is running a POP2 daemon that allows cleartext logins over
  unencrypted connections." );
	script_tag( name: "impact", value: "An attacker can uncover login names and
  passwords by sniffing traffic to the POP2 daemon." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
port = get_kb_item( "Services/pop2" );
if(!port){
	port = 109;
}
if(!get_port_state( port )){
	exit( 0 );
}
encaps = get_port_transport( port );
if(encaps > ENCAPS_IP){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
r = recv_line( socket: soc, length: 4096 );
close( soc );
if(!r || !ContainsString( r, "POP" )){
	exit( 0 );
}
security_message( port: port );
exit( 0 );

