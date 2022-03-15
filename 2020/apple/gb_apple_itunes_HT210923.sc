CPE = "cpe:/a:apple:itunes";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816615" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-3861" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-04 17:20:00 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-01-29 12:22:35 +0530 (Wed, 29 Jan 2020)" );
	script_name( "Apple iTunes Security Update(HT210923)" );
	script_tag( name: "summary", value: "Apple iTunes is prone to an access bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to improper permissions
  logic." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  gain access to protected parts of the file system." );
	script_tag( name: "affected", value: "Apple iTunes versions before 12.10.4." );
	script_tag( name: "solution", value: "Update to Apple iTunes 12.10.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT210923" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_apple_itunes_detection_win_900123.sc" );
	script_mandatory_keys( "iTunes/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "12.10.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "12.10.4", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

