CPE = "cpe:/a:phpgroupware:phpgroupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14292" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 8088 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2003-0504" );
	script_xref( name: "OSVDB", value: "2243" );
	script_name( "PhpGroupWare multiple HTML injection vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "phpgroupware_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpGroupWare/installed" );
	script_tag( name: "solution", value: "Update to version 0.9.14.005 or newer" );
	script_tag( name: "summary", value: "The remote host seems to be running PhpGroupWare, is a multi-user groupware
  suite written in PHP." );
	script_tag( name: "impact", value: "A malicious attacker may inject arbitrary HTML and script code using these
  form fields that may be incorporated into dynamically generated web content." );
	script_tag( name: "insight", value: "This version has been reported prone to multiple HTML injection vulnerabilities.
  The issues present themselves due to a lack of sufficient input validation
  performed on form fields used by PHPGroupWare modules." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(ereg( pattern: "^0\\.([0-8]\\.|9\\.([0-9]\\.|1[0-3]\\.|14\\.0*[0-3]([^0-9]|$)))", string: vers )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.9.14.005" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

