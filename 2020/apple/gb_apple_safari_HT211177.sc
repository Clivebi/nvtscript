CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817030" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-9801", "CVE-2020-9802", "CVE-2020-9805", "CVE-2020-9800", "CVE-2020-9806", "CVE-2020-9807", "CVE-2020-9850", "CVE-2020-9843", "CVE-2020-9803", "CVE-2019-20503" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-16 17:15:00 +0000 (Fri, 16 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-05-28 11:33:31 +0530 (Thu, 28 May 2020)" );
	script_name( "Apple Safari Security Update (HT211177)" );
	script_tag( name: "summary", value: "Apple Safari is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An out-of-bounds write/read issue with bounds checking,

  - A memory corruption issues input validation" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code, gain access to sensitive data, bypass security
  restrictions, and launch denial of service attacks." );
	script_tag( name: "affected", value: "Apple Safari versions before 13.1.1" );
	script_tag( name: "solution", value: "Update to Apple Safari 13.1.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT211177" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "13.1.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "13.1.1", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

