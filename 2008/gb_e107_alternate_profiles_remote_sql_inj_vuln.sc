CPE = "cpe:/a:e107:e107";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800303" );
	script_version( "2021-09-09T10:20:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 10:20:36 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2008-11-11 09:00:11 +0100 (Tue, 11 Nov 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-4785" );
	script_bugtraq_id( 31940 );
	script_name( "e107 alternate_profiles plugin newuser.php SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "e107_detect.sc" );
	script_mandatory_keys( "e107/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/6849" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to compromise the application,
  access or modify data in the underlying database." );
	script_tag( name: "affected", value: "e107 version 0.7.13, alternate_profiles plugin on all running platform." );
	script_tag( name: "insight", value: "The flaw exists in newuser.php file, which does not validate user input data
  in the alternate_profiles via the id parameter." );
	script_tag( name: "solution", value: "Upgrade to e107 version 0.7.22 or later." );
	script_tag( name: "summary", value: "This host is running e107 and is prone to remote SQL injection
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://e107.org/edownload.php" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/e107_plugins/alternate_profiles/newuser.php";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "newuser" ) && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

