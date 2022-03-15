CPE = "cpe:/a:apple:itunes";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810989" );
	script_version( "2021-09-10T09:01:40+0000" );
	script_cve_id( "CVE-2017-6984" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-08 16:06:00 +0000 (Fri, 08 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-05-16 12:30:16 +0530 (Tue, 16 May 2017)" );
	script_name( "Apple iTunes Code Execution Vulnerability-HT207805 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Apple iTunes
  and is prone to code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to multiple memory
  corruption issues." );
	script_tag( name: "impact", value: "Successful exploitation will lead to
  arbitrary code execution." );
	script_tag( name: "affected", value: "Apple iTunes versions before 12.6.1 on
  Windows." );
	script_tag( name: "solution", value: "Upgrade to Apple iTunes 12.6.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207805" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "12.6.1.25" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "12.6.1", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

