CPE = "cpe:/a:apple:xcode";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817898" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2020-5260" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-19 18:21:00 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-01-28 12:48:59 +0530 (Thu, 28 Jan 2021)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Apple Xcode Path Traversal Vulnerability (HT212153)" );
	script_tag( name: "summary", value: "Apple Xcode is prone to a path traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a path handling error
  related to improper input validation." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to access arbitrary files on the host device while running an app
  that uses on-demand resources with Xcode." );
	script_tag( name: "affected", value: "Apple Xcode prior to version 12.4" );
	script_tag( name: "solution", value: "Upgrade to Apple Xcode 12.4 or later.
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT212153" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gather-package-list.sc", "gb_xcode_detect_macosx.sc" );
	script_mandatory_keys( "ssh/login/osx_version", "Xcode/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || version_is_less( version: osVer, test_version: "10.15.4" )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
xcVer = infos["version"];
xcpath = infos["location"];
if(version_is_less( version: xcVer, test_version: "12.4" )){
	report = report_fixed_ver( installed_version: xcVer, fixed_version: "12.4", install_path: xcpath );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

