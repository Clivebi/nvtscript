if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902952" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_bugtraq_id( 57948 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-02-26 11:48:51 +0530 (Tue, 26 Feb 2013)" );
	script_name( "AbanteCart Multiple Cross-Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52165" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/82073" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2013020095" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120273" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/52165" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5125.php" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "AbanteCart version 1.1.3 and prior" );
	script_tag( name: "insight", value: "Input passed via the 'limit', 'page', 'rt', 'sort', 'currency',
  'product_id', 'language', 's', 'manufacturer_id', and 'token' GET parameters
  to index.php is not properly sanitized before being returned to the user." );
	script_tag( name: "solution", value: "Upgrade to version 1.1.4 or later." );
	script_tag( name: "summary", value: "This host is installed with AbanteCart and is prone to multiple
  cross site scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.abantecart.com" );
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
for dir in nasl_make_list_unique( "/", "/abantecart", "/cart", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: port );
	if(!res){
		continue;
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, ">AbanteCart<" ) && ContainsString( res, ">Powered by Abantecart" ) && ContainsString( res, ">Cart<" )){
		url = dir + "/index.php?limit=\"><script>alert(document.cookie);</script>";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "><script>alert\\(document\\.cookie\\);</script>", extra_check: ">AbanteCart<" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

