if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100840" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-10-04 14:08:22 +0200 (Mon, 04 Oct 2010)" );
	script_bugtraq_id( 43628 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Zen Cart Multiple Input Validation Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/43628" );
	script_xref( name: "URL", value: "http://www.zen-cart.com/" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4967.php" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4966.php" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the reference for more details." );
	script_tag( name: "summary", value: "Zen Cart is prone to multiple input-validation vulnerabilities because
it fails to adequately sanitize user-supplied input. These
vulnerabilities include local file-include, SQL-injection, and HTML-
injection issues.

Exploiting these issues can allow attacker-supplied HTML and script
code to run in the context of the affected browser, allowing attackers
to steal cookie-based authentication credentials, view local files
within the context of the webserver, compromise the application,
access or modify data, or exploit latent vulnerabilities in the
underlying database. Other attacks may also be possible.

Zen Cart v1.3.9f is vulnerable, other versions may also be affected." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/shop", "/cart", "/zen-cart", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in keys( files ) {
		url = NASLString( dir, "/index.php?typefilter=", crap( data: "..%2f", length: 9 * 5 ), files[file], "%00" );
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

