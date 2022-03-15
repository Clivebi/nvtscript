CPE = "cpe:/a:isc:bind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143077" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-10-30 06:34:43 +0000 (Wed, 30 Oct 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-6475", "CVE-2019-6476" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ISC BIND 9.14.0 < 9.14.7, 9.15.0 < 9.15.5 Multiple Vulnerabilities - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_isc_bind_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "isc/bind/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "ISC BIND is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "ISC BIND is prone to multiple vulnerabilities:

  - A flaw in mirror zone validity checking can allow zone data to be spoofed (CVE-2019-6475)

  - An error in QNAME minimization code can cause BIND to exit with an assertion failure (CVE-2019-6476)" );
	script_tag( name: "impact", value: "An on-path attacker who manages to successfully exploit this vulnerability can
  replace the mirrored zone (usually the root) with data of their own choosing, effectively bypassing DNSSEC
  protection (CVE-2019-6475) and an attacker who manages to deliberately trigger this condition on a server which
  is performing recursion can cause named to exit, denying service to clients (CVE-2019-6476)." );
	script_tag( name: "affected", value: "ISC BIND versions 9.14.0 to 9.14.6 and 9.15.0 to 9.15.4." );
	script_tag( name: "solution", value: "Update to version 9.14.7, 9.15.5 or later." );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/cve-2019-6475" );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/cve-2019-6476" );
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
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.14.0", test_version2: "9.14.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.14.7", install_path: location );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.15.0", test_version2: "9.15.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.15.5", install_path: location );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );

