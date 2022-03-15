CPE = "cpe:/a:oracle:openjdk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150709" );
	script_version( "2021-09-08T07:50:37+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 07:50:37 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-08-24 09:33:19 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-09 00:00:00 +0000 (Mon, 09 Aug 2021)" );
	script_cve_id( "CVE-2021-2388", "CVE-2021-2369", "CVE-2021-2432", "CVE-2021-2341" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle OpenJDK Multiple Vulnerabilities (Jul 2021)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_openjdk_detect.sc" );
	script_mandatory_keys( "openjdk/detected" );
	script_tag( name: "summary", value: "Oracle OpenJDK is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the
  vulnerabilities." );
	script_tag( name: "affected", value: "Oracle OpenJDK versions 16.0.1, 15.0.3, 13.0.7, 11.0.11, 8u292
  (1.8.0.292), 7u301 (1.7.0.301) and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for
  more information." );
	script_xref( name: "URL", value: "https://openjdk.java.net/groups/vulnerability/advisories/2021-07-20" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^16" ) && version_is_less_equal( version: vers, test_version: "16.0.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See advisory", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( vers, "^15" ) && version_is_less_equal( version: vers, test_version: "15.0.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See advisory", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( vers, "^13" ) && version_is_less_equal( version: vers, test_version: "13.0.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See advisory", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( vers, "^11" ) && version_is_less_equal( version: vers, test_version: "11.0.11" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See advisory", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( vers, "^1\\.8" ) && version_is_less_equal( version: vers, test_version: "1.8.0.292" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See advisory", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( vers, "^1\\.7" ) && version_is_less_equal( version: vers, test_version: "1.7.0.301" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See advisory", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

