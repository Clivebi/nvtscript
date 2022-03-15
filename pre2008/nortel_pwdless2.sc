if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10529" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Nortel Networks passwordless router (user level)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2000 Victor Kirhenshtein" );
	script_family( "Default Accounts" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/nortel_bay_networks/device/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Telnet to this router and set a password immediately." );
	script_tag( name: "summary", value: "The remote Nortel Networks (former Bay Networks) router has
  no password for user account." );
	script_tag( name: "impact", value: "An attacker could telnet to the router and reconfigure it to lock
  you out of it, and to prevent you to use your internet connection." );
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
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || !ContainsString( banner, "Bay Networks" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
buf = telnet_negotiate( socket: soc );
if(ContainsString( buf, "Bay Networks" )){
	if(ContainsString( buf, "Login:" )){
		data = NASLString( "User\\r\\n" );
		send( socket: soc, data: data );
		buf2 = recv( socket: soc, length: 1024 );
		close( soc );
		if(ContainsString( buf2, "$" )){
			security_message( port: port );
			exit( 0 );
		}
		exit( 99 );
	}
}
close( soc );
exit( 99 );

