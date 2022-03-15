if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802387" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-02-01 13:14:14 +0530 (Wed, 01 Feb 2012)" );
	script_name( "SolGens E-Commerce 'cid' And 'pid' Parameters SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/108947/solgensecommerce-sql.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to perform SQL injection
  attack and gain sensitive information." );
	script_tag( name: "affected", value: "SolGens E-Commerce" );
	script_tag( name: "insight", value: "The flaws are caused by improper validation of user-supplied input
  sent via the 'cid' and 'pid' parameters to 'product_detail.php',
  'category_products.php' and 'order_product.php' scripts, which allows
  attackers to manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running SolGens E-Commerce and is prone to SQL injection
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/solgens", "/SolGens", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(egrep( pattern: ">.?SolGens", string: rcvRes )){
		url = dir + "/product_detail.php?pid='";
		if(http_vuln_check( port: port, url: url, pattern: ">Warning<.*supplied " + "argument is not a valid MySQL result resource in.*product_detail.php" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

