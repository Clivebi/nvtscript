if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12641" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-1999-0502" );
	script_name( "Default password router Pirelli AGE mB" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 1999 Anonymous" );
	script_family( "Default Accounts" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/banner/available" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Telnet to this router and set a password immediately." );
	script_tag( name: "summary", value: "The remote host is a Pirelli AGE mB (microBusiness) router with its
  default password set (admin/microbusiness)." );
	script_tag( name: "impact", value: "An attacker could telnet to it and reconfigure it to lock the owner out
  and to prevent him from using his Internet connection, and do bad things." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("default_account.inc.sc");
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || !ContainsString( banner, "USER:" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(soc){
	r = recv_until( socket: soc, pattern: "(USER:|ogin:)" );
	if(!ContainsString( r, "USER:" )){
		close( soc );
		exit( 0 );
	}
	s = NASLString( "admin\\r\\nmicrobusiness\\r\\n" );
	send( socket: soc, data: s );
	r = recv_until( socket: soc, pattern: "Configuration" );
	close( soc );
	if(r && ContainsString( r, "Configuration" )){
		security_message( port: port );
		exit( 0 );
	}
}
soc = open_sock_tcp( port );
if(soc){
	r = recv_until( socket: soc, pattern: "(USER:|ogin:)" );
	if(!ContainsString( r, "USER:" )){
		close( soc );
		exit( 0 );
	}
	s = NASLString( "user\\r\\npassword\\r\\n" );
	send( socket: soc, data: s );
	r = recv_until( socket: soc, pattern: "Configuration" );
	close( soc );
	if(r && ContainsString( r, "Configuration" )){
		security_message( port: port );
	}
}
exit( 0 );

