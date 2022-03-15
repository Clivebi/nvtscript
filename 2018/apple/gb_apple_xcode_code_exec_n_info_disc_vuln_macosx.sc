CPE = "cpe:/a:apple:xcode";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813606" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-11235", "CVE-2018-11233" );
	script_bugtraq_id( 104345, 104346 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-02 00:15:00 +0000 (Sat, 02 May 2020)" );
	script_tag( name: "creation_date", value: "2018-06-14 10:59:39 +0530 (Thu, 14 Jun 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Apple Xcode Code Execution And Information Disclosure Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Apple Xcode
  and is prone to code execution and information disclosure vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Git software does not properly validate submodule 'names' supplied via the
    untrusted .gitmodules file when appending them to the '$GIT_DIR/modules'
    directory.

  - An input validation flaw in processing path names on NTFS-based systems to
    read random memory contents." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to execute arbitrary code and to obtain sensitive information
  that may lead to further attacks." );
	script_tag( name: "affected", value: "Apple Xcode prior to version 9.4.1" );
	script_tag( name: "solution", value: "Upgrade to Apple Xcode 9.4.1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT208895" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gather-package-list.sc", "gb_xcode_detect_macosx.sc" );
	script_mandatory_keys( "ssh/login/osx_version", "Xcode/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || version_is_less( version: osVer, test_version: "10.13.2" )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
xcVer = infos["version"];
xcpath = infos["location"];
if(version_is_less( version: xcVer, test_version: "9.4.1" )){
	report = report_fixed_ver( installed_version: xcVer, fixed_version: "9.4.1", install_path: xcpath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

