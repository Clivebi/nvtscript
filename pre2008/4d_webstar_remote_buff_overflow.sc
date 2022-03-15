if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18212" );
	script_version( "2019-12-18T08:24:18+0000" );
	script_tag( name: "last_modification", value: "2019-12-18 08:24:18 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2005-1507" );
	script_bugtraq_id( 13538, 14192 );
	script_xref( name: "OSVDB", value: "16154" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "4D WebStar Tomcat Plugin Remote Buffer Overflow flaw" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "gb_webstar_detect.sc" );
	script_mandatory_keys( "4d/webstar/detected" );
	script_tag( name: "solution", value: "Upgrade to latest version of this software." );
	script_tag( name: "summary", value: "The remote 4D WebStar Web Server is vulnerable to a remote buffer overflow
  in its Tomcat plugin." );
	script_tag( name: "impact", value: "A malicious user may be able to crash service or execute
  arbitrary code on the computer with the privileges of the HTTP server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:4d:webstar";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "5.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Update to the latest version", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

