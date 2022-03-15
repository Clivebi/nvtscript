CPE = "cpe:/a:dotnetnuke:dotnetnuke";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902515" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-11 15:50:14 +0200 (Wed, 11 May 2011)" );
	script_cve_id( "CVE-2010-4514" );
	script_bugtraq_id( 45180 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "DotNetNuke 'InstallWizard.aspx' Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dotnetnuke_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "dotnetnuke/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42478" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1024828" );
	script_xref( name: "URL", value: "http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr10-19" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of an
  affected site." );
	script_tag( name: "affected", value: "DotNetNuke versions 5.05.01 and 5.06.00." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input to the
  '__VIEWSTATE' parameter in Install/InstallWizard.aspx, which allows attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "solution", value: "Update to DotNetNuke version 5.06.02 or later." );
	script_tag( name: "summary", value: "This host is running DotNetNuke and is prone to cross site
  scripting vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
url = dir + "/Install/InstallWizard.aspx?__VIEWSTATE=<script>alert('vt-xss-test')</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "ViewState: <script>alert\\('vt-xss-test'\\)</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

