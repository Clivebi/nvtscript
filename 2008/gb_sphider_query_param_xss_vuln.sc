if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800308" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-12-01 15:31:19 +0100 (Mon, 01 Dec 2008)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2008-5211" );
	script_bugtraq_id( 29074 );
	script_name( "Sphider query Parameter Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/42240" );
	script_xref( name: "URL", value: "http://users.own-hero.net/~decoder/advisories/sphider134-xss.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful attack could lead to execution of arbitrary HTML or scripting code
  in the security context of an affected web page, which allows an attacker to
  steal cookie-based authentication credentials or access and modify data." );
	script_tag( name: "affected", value: "Sphider Version 1.3.4 and prior on all running platform." );
	script_tag( name: "insight", value: "The flaw is due to input passed into the query parameter in search.php
  when suggestion feature is enabled is not properly sanitized before being returned to a user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Sphider and is prone to cross-site scripting
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for path in nasl_make_list_unique( "/sphider", http_cgi_dirs( port: port ) ) {
	if(path == "/"){
		path = "";
	}
	rcvRes = http_get_cache( item: path + "/changelog", port: port );
	if(!rcvRes){
		continue;
	}
	if(egrep( pattern: "Sphider .* search engine in PHP", string: rcvRes )){
		sphiderVer = eregmatch( pattern: "Sphider ([0-9.]+)", string: rcvRes );
		if(sphiderVer[1] != NULL){
			if(version_is_less_equal( version: sphiderVer[1], test_version: "1.3.4" )){
				security_message( port: port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

