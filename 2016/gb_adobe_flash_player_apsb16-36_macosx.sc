CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809464" );
	script_version( "2021-09-08T12:28:17+0000" );
	script_cve_id( "CVE-2016-7855" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-08 12:28:17 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-10-27 18:42:32 +0530 (Thu, 27 Oct 2016)" );
	script_name( "Adobe Flash Player Security Update (apsb16-36) - MAC OS X" );
	script_tag( name: "summary", value: "Adobe Flash Player is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a use-after-free vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to take control of the affected system." );
	script_tag( name: "affected", value: "Adobe Flash Player version
  22.x before 23.0.0.205." );
	script_tag( name: "solution", value: "Update to version 23.0.0.205 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb16-36.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Flash/Player/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "22", test_version2: "23.0.0.204" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "23.0.0.205", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

