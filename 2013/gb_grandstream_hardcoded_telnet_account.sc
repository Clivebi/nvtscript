if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103737" );
	script_version( "2021-07-02T11:00:44+0000" );
	script_cve_id( "CVE-2013-3542", "CVE-2013-3962", "CVE-2013-3963" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Grandstream Devices Backdoor in Telnet Protocol" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2013/Jun/84" );
	script_tag( name: "last_modification", value: "2021-07-02 11:00:44 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-19 20:21:00 +0000 (Thu, 19 Dec 2019)" );
	script_tag( name: "creation_date", value: "2013-06-11 14:29:08 +0200 (Tue, 11 Jun 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "The remote Grandstream device has the default telnet user and password '!#/'." );
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
buf = recv( socket: soc, length: 512 );
if(!ContainsString( buf, "grandstream" ) || !ContainsString( buf, "Username" )){
	exit( 0 );
}
up = "!#/";
send( socket: soc, data: up + "\r\n" );
ret = recv( socket: soc, length: 512 );
if(!ContainsString( ret, "Password" )){
	exit( 0 );
}
send( socket: soc, data: up + "\r\n" );
ret = recv( socket: soc, length: 512 );
close( soc );
if(ContainsString( ret, "Grandstream>" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

