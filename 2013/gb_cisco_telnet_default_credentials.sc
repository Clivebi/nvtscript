if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103807" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-10-11 17:38:09 +0200 (Fri, 11 Oct 2013)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_name( "Cisco Default Telnet Login" );
	script_category( ACT_ATTACK );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/cisco/ios/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Change the password as soon as possible." );
	script_tag( name: "summary", value: "It was possible to login into the remote host using default credentials." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_timeout( 600 );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("default_credentials.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!ContainsString( banner, "User Access Verification" ) && !ContainsString( banner, "cisco" )){
	exit( 0 );
}
default = try( vendor: "cisco" );
if(!default){
	exit( 0 );
}
for pw in default {
	up = split( buffer: pw, sep: ":", keep: FALSE );
	if(isnull( up[0] ) || isnull( up[1] )){
		continue;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		continue;
	}
	user = up[0];
	pass = up[1];
	if(tolower( pass ) == "none"){
		pass = "";
	}
	send( socket: soc, data: user + "\r\n" );
	ret = recv( socket: soc, length: 1024 );
	if(!ContainsString( ret, "ass" )){
		close( soc );
		sleep( 1 );
		continue;
	}
	send( socket: soc, data: pass + "\r\n" );
	ret = recv( socket: soc, length: 1024 );
	send( socket: soc, data: "show ver\r\n" );
	ret = recv( socket: soc, length: 4096 );
	close( soc );
	if(ContainsString( ret, "Cisco IOS Software" ) || ContainsString( ret, "Cisco Internetwork Operating System Software" )){
		report = "It was possible to login as user \"" + user + "\" with password \"" + pass + "\".\n";
		;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

