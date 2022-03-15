if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805356" );
	script_version( "2020-11-19T14:17:11+0000" );
	script_cve_id( "CVE-2015-2780" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-04-07 12:32:43 +0530 (Tue, 07 Apr 2015)" );
	script_name( "Berta CMS Arbitrary File Upload Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Berta CMS
  is prone to file upload vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to upload file or not." );
	script_tag( name: "insight", value: "The flaw is due to an input passed via
  the 'uploads.php' script is not properly sanitised before being used." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to utilize various admin functionality, execute any
  arbitrary script, and expose potentially sensitive information." );
	script_tag( name: "affected", value: "Berta CMS version before 0.8.10b." );
	script_tag( name: "solution", value: "Upgrade to Berta CMS version 0.8.10b
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "exploit" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Mar/155" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/03/30/7" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/131041/Berta-CMS-File-Upload-Bypass.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.berta.me" );
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
for dir in nasl_make_list_unique( "/", "/engine", "/berta/engine", "/berta", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/login.php";
	rcvRes = http_get_cache( item: url, port: http_port );
	if(rcvRes && ContainsString( rcvRes, "berta v" ) && ContainsString( rcvRes, "Log in" )){
		url = dir + "/upload.php";
		if(http_vuln_check( port: http_port, url: url, pattern: "O*error" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

