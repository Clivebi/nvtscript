CPE = "cpe:/a:phpgroupware:phpgroupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14295" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 9387 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "OSVDB", value: "6860" );
	script_cve_id( "CVE-2004-0016" );
	script_name( "PhpGroupWare calendar server side script execution" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "phpgroupware_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpGroupWare/installed" );
	script_tag( name: "solution", value: "Update to version 0.9.14.007 or newer" );
	script_tag( name: "summary", value: "The remote host is running a version of PhpGroupware which is vulnerable
  to a remote attack.

  PhpGroupWare is a multi-user groupware suite written in PHP." );
	script_tag( name: "insight", value: "It has been reported that this version may be prone to a vulnerability that
  may allow remote attackers to execute malicious scripts on a vulnerable system.
  The flaw allows remote attackers to upload server side scripts which can then
  be executed on the server." );
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
if(ereg( pattern: "^0\\.([0-8]\\.|9\\.([0-9]\\.|1[0-3]\\.|14\\.0*[0-6]([^0-9]|$)))", string: vers )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.9.14.007" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

