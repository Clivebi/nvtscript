if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103001" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-01-03 14:40:34 +0100 (Mon, 03 Jan 2011)" );
	script_bugtraq_id( 45568 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_name( "Appweb Web Server Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/45568" );
	script_xref( name: "URL", value: "http://appwebserver.org/" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4985.php" );
	script_xref( name: "URL", value: "http://appwebserver.org/downloads/appweb/download.php" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Embedthis-Appweb/banner" );
	script_tag( name: "solution", value: "Updates are available. Please see the reference for more details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Appweb is prone to a cross-site scripting vulnerability because it
fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

Appweb 3.2.2-1 is vulnerable. Other versions may also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: Embedthis-Appweb/" )){
	exit( 0 );
}
vt_strings = get_vt_strings();
url = NASLString( "/ejs/%3Cscript%3Ealert%28%27", vt_strings["lowercase"], "%27%29%3C/script%3E" );
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('" + vt_strings["lowercase"] + "'\\)</script>", extra_check: make_list( "Ejscript error" ), check_header: TRUE )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

