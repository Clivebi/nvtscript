if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804874" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-7985", "CVE-2014-7986", "CVE-2014-7987" );
	script_bugtraq_id( 70809, 70811, 70806 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-10-30 12:02:52 +0530 (Thu, 30 Oct 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_name( "EspoCRM '/install/index.php' Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with EspoCRM and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple errors are due to:

  - Improper sanitization of input passed via 'action' and 'desc' HTTP GET
  parameters to /install/index.php script.

  - Insufficient access control restriction to the installation script
  /install/index.php." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser session
  in the context of an affected site, include and execute arbitrary local PHP
  files on the system with privileges of the web server, and reinstall the
  application." );
	script_tag( name: "affected", value: "EspoCRM version 2.5.2 and probably
  earlier." );
	script_tag( name: "solution", value: "Upgrade to EspoCRM version 2.6.0 or later." );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23238" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/533844" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.espocrm.com/" );
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
for dir in nasl_make_list_unique( "/", "/EspoCRM", "/crm", "/CRM", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(rcvRes && ContainsString( rcvRes, ">EspoCRM<" ) && IsMatchRegexp( rcvRes, ">&copy.*>EspoCRM<" )){
		url = dir + "/install/index.php?installProcess=1&action=errors&d" + "esc=<script>alert(document.cookie);</script>";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\);</script>", extra_check: make_list( ">EspoCRM<",
			 "License Agreement" ) )){
			report = http_report_vuln_url( port: http_port, url: url );
			security_message( port: http_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

