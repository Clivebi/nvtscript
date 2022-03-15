if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804857" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-09-26 12:24:19 +0530 (Fri, 26 Sep 2014)" );
	script_name( "Cart Engine Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is running Cart Engine and is
  prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET
  request and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple errors exist due to:

  - Insufficient validation of the input parameters 'item_id[0]' and 'item_id[]'
    passed to cart.php page.

  - Insufficient sanitization of multiple pages output which includes the user
    submitted content.

  - Insufficient validation of the user-supplied input in index.php, cart.php,
    msg.php and page.php scripts." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  conduct open-redirect attacks and execute arbitrary HTML and script code in a
  user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Cart Engine version 3.0. Other versions
  may also be affected." );
	script_tag( name: "solution", value: "Upgrade to Cart Engine 4.0 or later." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://1337day.com/exploit/22690" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/34764/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/128276" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.c97.net/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 80 );
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/cartengine", "/cart", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(rcvRes && IsMatchRegexp( rcvRes, "powered by qEngine.*CartEngine" )){
		url = dir + "/index.php?';alert('XSS-Test')//";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: ";alert\\('XSS-Test'\\)//", extra_check: "powered by qEngine" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

