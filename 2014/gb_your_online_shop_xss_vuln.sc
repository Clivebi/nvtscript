if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805000" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-6618" );
	script_bugtraq_id( 70073 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-10-16 16:50:50 +0530 (Thu, 16 Oct 2014)" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Your Online Shop 'products_id' Parameter Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Your Online Shop
  and is prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "This flaw exists due to an insufficient sanitization
  of input to the 'products_id' parameter before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site." );
	script_tag( name: "affected", value: "Your Online Shop version 1.1.8.6.1, Other
  versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/96163" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/128336" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
serPort = http_get_port( default: 80 );
if(!http_can_host_php( port: serPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/youronlineshop", "/cart", "/shop", http_cgi_dirs( port: serPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: serPort );
	if(ContainsString( res, "www.tecnibur.com/youronlineshop/" ) && ContainsString( res, ">Your online shop<" )){
		url = dir + "/?seccion=ver_prod&products_id=test\"/><script>alert(document.cookie)</script><";
		if(http_vuln_check( port: serPort, url: url, check_header: TRUE, pattern: "><script>alert\\(document.cookie\\)</script><", extra_check: "nameLargeProdtest" )){
			security_message( port: serPort );
			exit( 0 );
		}
	}
}
exit( 99 );

