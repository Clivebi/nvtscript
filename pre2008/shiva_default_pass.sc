if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10500" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-1999-0508" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Shiva Integrator Default Password" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2000 Stefaan Van Dooren" );
	script_family( "Default Accounts" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/banner/available" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Telnet to this router and set a different password immediately." );
	script_tag( name: "summary", value: "The remote Shiva router uses the default password.
  This means that anyone who has (downloaded) a user manual can
  telnet to it and reconfigure it to lock you out of it, and to
  prevent you to use your internet connection." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = telnet_get_port( default: 23 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
data = NASLString( "hello\\n\\r" );
send( data: data, socket: soc );
buf = recv( socket: soc, length: 4096 );
close( soc );
if(ContainsString( buf, "ntering privileged mode" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

