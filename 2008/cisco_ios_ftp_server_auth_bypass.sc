if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.9999996" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2007-2586" );
	script_bugtraq_id( 23885 );
	script_name( "Cisco IOS FTP Server Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_active" );
	script_family( "FTP" );
	script_copyright( "Copyright (C) 2008 Ferdy Riphagen" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/cisco/ios_ftp/detected" );
	script_tag( name: "summary", value: "The Cisco IOS FTP server is enabled on the remote system
  which does not properly verify authentication, allowing for anonymous access to the file system." );
	script_tag( name: "impact", value: "An attacker could use the ftp server to view/download confidential
  configuration files, or upload replacements which will be used at startup." );
	script_xref( name: "URL", value: "http://www.cisco.com/en/US/products/products_security_advisory09186a00808399d0.shtml" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
func start_passive( port, soc ){
	pasv = ftp_pasv( socket: soc );
	if(!pasv){
		return NULL;
	}
	soc2 = open_sock_tcp( port: pasv, transport: get_port_transport( port ) );
	if(!soc2){
		return NULL;
	}
	return;
}
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "IOS-FTP server" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(soc && ( ftp_authenticate( socket: soc, user: "blah", pass: "blah" ) )){
	if(start_passive( port: port, soc: soc )){
		send( socket: soc, data: "LIST\r\n" );
		recv_listing = ftp_recv_listing( socket: soc2 );
		ftp_close( socket: soc2 );
	}
}
if(soc){
	ftp_close( socket: soc );
}
if(strlen( recv_listing )){
	soc = open_sock_tcp( port );
	if(soc && ( ftp_authenticate( socket: soc, user: "blah", pass: "blah" ) )){
		send( socket: soc, data: "CWD nvram:\r\n" );
		recv = ftp_recv_line( socket: soc, retry: 1 );
		if(ContainsString( recv, "250" ) && ( start_passive( port: port, soc: soc ) )){
			send( socket: soc, data: "RETR startup-config\r\n" );
			recv_config = ftp_recv_data( socket: soc2, line: 500 );
			ftp_close( socket: soc2 );
		}
	}
}
if(soc){
	ftp_close( socket: soc );
}
if( strlen( recv_config ) ){
	report = NASLString( "Partial startup-config file:\\r\\n", recv_config );
	security_message( port: port, data: report );
	exit( 0 );
}
else {
	if(strlen( recv_listing )){
		security_message( port: port );
		exit( 0 );
	}
}

