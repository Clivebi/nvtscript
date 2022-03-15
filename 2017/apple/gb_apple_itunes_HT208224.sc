CPE = "cpe:/a:apple:itunes";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811957" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_cve_id( "CVE-2017-13784", "CVE-2017-13785", "CVE-2017-13783", "CVE-2017-13788", "CVE-2017-13795", "CVE-2017-13802", "CVE-2017-13792", "CVE-2017-13791", "CVE-2017-13798", "CVE-2017-13796", "CVE-2017-13793", "CVE-2017-13794", "CVE-2017-13803" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-22 19:11:00 +0000 (Fri, 22 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-11-02 17:19:55 +0530 (Thu, 02 Nov 2017)" );
	script_name( "Apple iTunes Security Update (HT208224) - Windows" );
	script_tag( name: "summary", value: "Apple iTunes is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple
  memory corruption issues." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow remote attackers to perform arbitrary code execution." );
	script_tag( name: "affected", value: "Apple iTunes versions before 12.7.1." );
	script_tag( name: "solution", value: "Update to version 12.7.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT208224" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_apple_itunes_detection_win_900123.sc" );
	script_mandatory_keys( "iTunes/Win/Installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "12.7.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "12.7.1", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

