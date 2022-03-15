if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802402" );
	script_version( "2021-08-17T16:54:04+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-17 16:54:04 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-11-10 12:48:30 +0530 (Thu, 10 Nov 2011)" );
	script_name( "LabWiki Multiple Cross-site Scripting (XSS) and Shell Upload Vulnerabilities" );
	script_xref( name: "URL", value: "https://secunia.com/advisories/46762" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18100/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/520441" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/current/0112.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaws are due to an:

  - Input passed to the 'from' parameter in index.php is not properly sanitised
  before being returned to the user.

  - Input passed to the 'page_no' parameter in recentchanges.php is noti
  properly sanitised before being returned to the user.

  - Input passed to the 'userfile' POST parameter in edit.php is not properly
  verified before being used to upload files." );
	script_tag( name: "solution", value: "Update to version 1.2 or later." );
	script_tag( name: "summary", value: "This host is running LabWiki and is prone to multiple cross-site
  scripting and shell upload vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in context of
  affected website and to upload arbitrary PHP files with '.gif' extension." );
	script_tag( name: "affected", value: "LabWiki version 1.1 and prior." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
for dir in nasl_make_list_unique( "/LabWiki", "/labwiki/LabWiki", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, ">My Lab</a" ) && ContainsString( res, ">What is Wiki</" )){
		url = NASLString( dir, "/index.php?from=\"></><script>alert(document.cookie)" + "</script>&help=true&page=What_is_wiki" );
		if(http_vuln_check( port: port, url: url, pattern: "><script>alert" + "\\(document.cookie\\)</script>", check_header: TRUE )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

