CPE = "cpe:/a:vbulletin:vbulletin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14792" );
	script_version( "2019-09-27T07:10:39+0000" );
	script_tag( name: "last_modification", value: "2019-09-27 07:10:39 +0000 (Fri, 27 Sep 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 10612, 10602 );
	script_xref( name: "OSVDB", value: "7256" );
	script_cve_id( "CVE-2004-0620" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "vBulletin XSS" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "vbulletin_detect.sc" );
	script_mandatory_keys( "vbulletin/detected" );
	script_tag( name: "solution", value: "Upgrade to vBulletin 3.0.2 or newer." );
	script_tag( name: "summary", value: "The remote version of vBulletin is vulnerable
  to a cross-site scripting issue, due to a failure of the application to properly
  sanitize user-supplied URI input." );
	script_tag( name: "impact", value: "As a result of this vulnerability, it is possible
  for a remote attacker to create a malicious link containing script code that will be
  executed in the browser of an unsuspecting user when followed.

  This may facilitate the theft of cookie-based authentication credentials
  as well as other attacks." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "3.0.0", test_version2: "3.0.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.0.2", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

