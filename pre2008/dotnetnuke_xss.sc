CPE = "cpe:/a:dotnetnuke:dotnetnuke";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18505" );
	script_version( "$Revision: 13975 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2005-0040" );
	script_bugtraq_id( 13644, 13646, 13647 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Multiple DotNetNuke HTML Injection Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Josh Zlatin-Amishav" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dotnetnuke_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "dotnetnuke/installed" );
	script_tag( name: "solution", value: "Upgrade to version 3.0.12 or greater" );
	script_tag( name: "summary", value: "The remote host is running DotNetNuke, a portal written in ASP.

  The remote software, according to its version number, contains several input
  validation flaws leading to the execution of attacker supplied HTML and script code." );
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
if(version_is_less( version: vers, test_version: "3.0.12" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.0.12" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

