CPE = "cpe:/a:cubecart:cubecart";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.02602" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)" );
	script_bugtraq_id( 48265 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CubeCart Multiple XSS and SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/68023" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/68022" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/102236/cubecart207-sqlxss.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_cubecart_detect.sc" );
	script_mandatory_keys( "cubecart/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to gain sensitive
  information, execute arbitrary scripts and execute SQL query." );
	script_tag( name: "affected", value: "CubeCart version 2.0.7." );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - An improper validation of user-supplied input to the 'cat_id' parameter in
  index.php, 'product' parameter in view_product.php and the 'add' parameter
  in view_cart.php, which allows attacker to manipulate SQL queries.

  - An improper validation of user-supplied input in search.php, which allows
  attackers to execute arbitrary HTML and script code on the web server." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running CubeCart and is prone to XSS and SQL injection
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
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
url = dir + "/index.php?cat_id='";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "mysql_num_rows()" ) && ContainsString( res, "mysql_fetch_array()" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

