CPE = "cpe:/a:oracle:openjdk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150650" );
	script_version( "2021-09-08T07:50:37+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 07:50:37 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-05-31 08:42:17 +0000 (Mon, 31 May 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)" );
	script_cve_id( "CVE-2019-7317", "CVE-2019-2821", "CVE-2019-2769", "CVE-2019-2762", "CVE-2019-2745", "CVE-2019-2816", "CVE-2019-2842", "CVE-2019-2786", "CVE-2019-2818", "CVE-2019-2766" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle OpenJDK Multiple Vulnerabilities (Jul 2019)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_openjdk_detect.sc" );
	script_mandatory_keys( "openjdk/detected" );
	script_tag( name: "summary", value: "Oracle OpenJDK is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the
  vulnerabilities." );
	script_tag( name: "affected", value: "Oracle OpenJDK versions 12.0.1, 11.0.3, 8u212 (1.8.0.212),
  7u221 (1.7.0.221) and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for
  more information." );
	script_xref( name: "URL", value: "https://openjdk.java.net/groups/vulnerability/advisories/2019-07-16" );
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
if(IsMatchRegexp( vers, "^12" ) && version_is_less_equal( version: vers, test_version: "12.0.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See advisory", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( vers, "^11" ) && version_is_less_equal( version: vers, test_version: "11.0.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See advisory", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( vers, "^1\\.8" ) && version_is_less_equal( version: vers, test_version: "1.8.0.212" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See advisory", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( vers, "^1\\.7" ) && version_is_less_equal( version: vers, test_version: "1.7.0.221" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See advisory", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

