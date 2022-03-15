if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803190" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-04-09 15:08:24 +0530 (Tue, 09 Apr 2013)" );
	script_name( "Aastra IP Telephone Hardcoded Telnet Password Security Bypass Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_require_ports( "Services/www", 80, "Services/telnet", 23 );
	script_dependencies( "gb_get_http_banner.sc", "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "Aastra_6753i/banner", "telnet/vxworks/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Apr/42" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/526207" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/aastra-ip-telephone-hardcoded-password" );
	script_tag( name: "insight", value: "Aastra 6753i IP Phone installs with default hardcoded
  administrator credentials (username/password combination)." );
	script_tag( name: "solution", value: "Upgrade to latest version of Aastra 6753i IP Telephone." );
	script_tag( name: "summary", value: "This host is running Aastra IP Telephone and is prone to
  security bypass vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to access the device
  and gain privileged access." );
	script_tag( name: "affected", value: "Aastra 6753i IP Telephone." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(!banner || !ContainsString( banner, "VxWorks login:" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: NASLString( "admin", "\\r\\n" ) );
res = recv( socket: soc, length: 4096 );
if(ContainsString( res, "Password:" )){
	send( socket: soc, data: NASLString( "[M]qozn~", "\\r\\n" ) );
	res = recv( socket: soc, length: 4096 );
	if(ContainsString( res, "->" ) && !ContainsString( res, "Login incorrect" )){
		report = "It was possible to login with the following hardcoded credentials: 'admin:[M]qozn~'";
		security_message( port: port, data: report );
		close( soc );
		exit( 0 );
	}
}
close( soc );
exit( 99 );

