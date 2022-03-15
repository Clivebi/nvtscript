CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103463" );
	script_bugtraq_id( 52986 );
	script_cve_id( "CVE-2012-1835" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "WordPress All-in-One Event Calendar Plugin Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52986" );
	script_xref( name: "URL", value: "http://theseednetwork.com/services/websites-and-software/software/all-in-one-event-calendar-wordpress/" );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23082" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/522292" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2012-04-12 10:32:26 +0200 (Thu, 12 Apr 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "summary", value: "All-in-One Event Calendar plugin for WordPress is prone to multiple
cross-site scripting vulnerabilities because it fails to properly
sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may let the attacker steal cookie-based authentication
credentials and launch other attacks." );
	script_tag( name: "affected", value: "All-in-One Event Calendar 1.4 is vulnerable, other prior versions may
also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
url = NASLString( dir, "/wp-content/plugins/all-in-one-event-calendar/app/view/save_successful.php?msg=<script>alert(/xss-test/);</script>" );
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/xss-test/\\);</script>", check_header: TRUE )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

