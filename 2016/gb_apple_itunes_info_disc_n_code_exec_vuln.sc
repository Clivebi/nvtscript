CPE = "cpe:/a:apple:itunes";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810202" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-4613", "CVE-2016-7578" );
	script_bugtraq_id( 93949 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-11-17 12:45:37 +0530 (Thu, 17 Nov 2016)" );
	script_name( "Apple iTunes Code Execution And Information Disclosure Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Apple iTunes
  and is prone to information disclosure and code execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An input validation error in state management.

  - Multiple memory corruption errors in memory handling" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code and disclose user information." );
	script_tag( name: "affected", value: "Apple iTunes versions before 12.5.2
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to Apple iTunes 12.5.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207274" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_apple_itunes_detection_win_900123.sc" );
	script_mandatory_keys( "iTunes/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "12.5.2.36" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "12.5.2", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

