CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818554" );
	script_version( "2021-09-24T05:06:20+0000" );
	script_cve_id( "CVE-2021-30846", "CVE-2021-30848", "CVE-2021-30849", "CVE-2021-30851" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-24 05:06:20 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-22 17:41:46 +0530 (Wed, 22 Sep 2021)" );
	script_name( "Apple Safari Security Update (HT212816)" );
	script_tag( name: "summary", value: "The host is missing an important security
  update according to Apple." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple memory corruption
  issues in WebKit." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to
  conduct arbitrary code execution." );
	script_tag( name: "affected", value: "Apple Safari versions prior to 15 on macOS" );
	script_tag( name: "solution", value: "Update to Apple Safari 15 or later. Please see the
  references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT212816" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version", "ssh/login/osx_version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("ssh_func.inc.sc");
require("host_details.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || ( !IsMatchRegexp( osVer, "^10\\.15\\." ) && !IsMatchRegexp( osVer, "^11\\." ) ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "15" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "15", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

