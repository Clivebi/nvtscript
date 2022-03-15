if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804824" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-4742", "CVE-2014-4743" );
	script_bugtraq_id( 68496, 68498 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-08-27 12:09:04 +0530 (Wed, 27 Aug 2014)" );
	script_name( "Kajona CMS Multiple Cross-Site Scripting Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Kajona CMS and is prone to multiple
  cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check whether it is able to read cookie
  or not." );
	script_tag( name: "insight", value: "Multiple flaws exist as,

  - the search_ajax.tpl and search_ajax_small.tpl scripts in the Search module
  does not validate input passed via the 'search' parameter.

  - the system/class_link.php script does not validate input passed via the
  'systemid' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to execute arbitrary script
  code in a user's browser session within the trust relationship between their
  browser and the server." );
	script_tag( name: "affected", value: "Kajona CMS version 4.4 and prior." );
	script_tag( name: "solution", value: "Upgrade to Kajona CMS version 4.5 or later." );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/94938" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/94434" );
	script_xref( name: "URL", value: "https://www.netsparker.com/critical-xss-vulnerability-in-kajonacms" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.kajona.de" );
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
for dir in nasl_make_list_unique( "/", "/kajona", "/cmf", "/framework", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(rcvRes && ContainsString( rcvRes, "Kajona<" )){
		url = dir + "/index.php?page=downloads&systemid=\"</script><script>aler" + "t(document.cookie)</script>&action=";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "><script>alert\\(document\\.cookie\\)</script>", extra_check: ">Kajona<" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

