CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817285" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-6492" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2020-09-02 11:51:00 +0530 (Wed, 02 Sep 2020)" );
	script_name( "Google Chrome WebGL Code Execution Vulnerability (Aug 2020) - Linux" );
	script_tag( name: "summary", value: "Google Chrome is prone to a code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaws exist due to WebGL component
  fails to correctly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  execute arbitrary code in the context of the browser." );
	script_tag( name: "affected", value: "Google Chrome version 81.0.4044.138, 84.0.4136.5 and 84.0.4143.7." );
	script_tag( name: "solution", value: "Update to Google Chrome version 85.0.4149.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.bleepingcomputer.com/news/security/google-chrome-85-fixes-webgl-code-execution-vulnerability/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "85.0.4149.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "85.0.4149.0", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

