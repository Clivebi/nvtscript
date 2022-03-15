if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103772" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Sitecom Devices Hard-coded credentials" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/sitecom-n300-n600-access-bypass" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-08-21 16:02:55 +0200 (Wed, 21 Aug 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "os_detection.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/banner/available" );
	script_require_keys( "Host/runs_unixoide" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "impact", value: "Attackers can exploit these issues to gain unauthorized access to the
  affected device and perform certain administrative actions." );
	script_tag( name: "vuldetect", value: "Start a telnet session with the hard-coded credentials." );
	script_tag( name: "insight", value: "A user can login to the Telnet service (with root privileges) using the
  hard-coded credential admin:1234. This administrative account is hard-coded
  and cannot be changed by a normal user." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The remote Sitecom Device is prone to a hard-coded credentials bypass
  vulnerability" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = telnet_get_port( default: 23 );
if(get_kb_item( "telnet/" + port + "/no_login_banner" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
buf = telnet_negotiate( socket: soc );
if(!ContainsString( buf, "login:" )){
	close( soc );
	exit( 0 );
}
send( socket: soc, data: "admin\r\n" );
buf = recv( socket: soc, length: 1024 );
if(!ContainsString( buf, "Password:" )){
	close( soc );
	exit( 0 );
}
send( socket: soc, data: "1234\r\n" );
buf = recv( socket: soc, length: 1024 );
if(!ContainsString( buf, "#" )){
	close( soc );
	exit( 0 );
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	send( socket: soc, data: "cat /" + file + "\r\n" );
	buf = recv( socket: soc, length: 1024 );
	if(egrep( string: buf, pattern: pattern )){
		close( soc );
		security_message( data: "The target was found to be vulnerable", port: port );
		exit( 0 );
	}
}
close( soc );
exit( 99 );

