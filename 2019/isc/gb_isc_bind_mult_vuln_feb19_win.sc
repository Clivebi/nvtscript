CPE = "cpe:/a:isc:bind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142034" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-02-25 08:35:13 +0700 (Mon, 25 Feb 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-05 16:58:00 +0000 (Tue, 05 Nov 2019)" );
	script_cve_id( "CVE-2018-5744", "CVE-2018-5745", "CVE-2019-6465" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ISC BIND Multiple Vulnerabilities (Feb 2019) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_isc_bind_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "isc/bind/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "ISC BIND is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "ISC BIND is prone to multiple vulnerabilities:

  - A specially crafted packet can cause named to leak memory (CVE-2018-5744)

  - An assertion failure can occur if a trust anchor rolls over to an unsupported key algorithm when using
    managed-keys (CVE-2018-5745)

  - Zone transfer controls for writable DLZ zones were not effective (CVE-2019-6465)" );
	script_tag( name: "affected", value: "ISC BIND versions 9.9.0-9.10.8-P1, 9.11.0-9.11.5-P2, 9.12.0-9.12.3-P2 and
  9.9.3-S1-9.11.5-S3." );
	script_tag( name: "solution", value: "Update to version 9.11.5-S5, 9.11.5-P4, 9.12.3-P4 or later." );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/cve-2018-5744" );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/cve-2018-5745" );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/cve-2019-6465" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_full( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
proto = infos["proto"];
location = infos["location"];
if(!IsMatchRegexp( version, "^9\\." )){
	exit( 99 );
}
if( IsMatchRegexp( version, "^9\\.(9|10)\\.[0-9]s[0-9]" ) ){
	if(version_in_range( version: version, test_version: "9.9.3s1", test_version2: "9.11.5s3" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.11.5-S5", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
}
else {
	if(version_in_range( version: version, test_version: "9.9.0", test_version2: "9.10.8p1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.11.5-P4", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
	if(version_in_range( version: version, test_version: "9.11.0", test_version2: "9.11.5p2" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.11.5-P4", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
	if(version_in_range( version: version, test_version: "9.12.0", test_version2: "9.12.3p2" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.12.3-P4", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
}
exit( 99 );

