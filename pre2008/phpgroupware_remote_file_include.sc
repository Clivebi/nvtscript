CPE = "cpe:/a:phpgroupware:phpgroupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14294" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2003-0504" );
	script_bugtraq_id( 8265 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "OSVDB", value: "2243" );
	script_name( "PhpGroupWare unspecified remote file include vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "phpgroupware_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpGroupWare/installed" );
	script_tag( name: "solution", value: "Update to version 0.9.14.006 or newer" );
	script_tag( name: "summary", value: "The remote host seems to be running PhpGroupWare, is a multi-user groupware
  suite written in PHP." );
	script_tag( name: "insight", value: "This version is prone to a vulnerability that may permit remote attackers,
  without prior authentication, to include and execute malicious PHP scripts.
  Remote users may influence URI variables to include a malicious PHP script
  on a remote system, it is possible to cause arbitrary PHP code to be executed." );
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
if(ereg( pattern: "^0\\.([0-8]\\.|9\\.([0-9]\\.|1[0-3]\\.|14\\.0*[0-5]([^0-9]|$)))", string: vers )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.9.14.006" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

