if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800738" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 35760 );
	script_cve_id( "CVE-2009-4680", "CVE-2009-4681" );
	script_name( "phpDirectorySource Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35941" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9226" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "Input passed to 'search.php' through 'st' parameter is not properly
  sanitised before being returned to the user and before being used in SQL queries." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running phpDirectorySource and is prone to multiple
  vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML or
  execute arbitrary SQL commands in the context of an affected site." );
	script_tag( name: "affected", value: "phpDirectorySource version 1.x" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
vt_strings = get_vt_strings();
for dir in nasl_make_list_unique( "/pds", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, "phpDirectorySource" )){
		req = http_get( item: NASLString( dir, "/search.php?sa=site&sk=a&nl=11&st=\">" + "<script>alert(\"", vt_strings["lowercase"], "\");</script>" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(( IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, vt_strings["lowercase"] ) )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

