CPE = "cpe:/a:isc:bind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142323" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-04-30 07:12:23 +0000 (Tue, 30 Apr 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-18 18:15:00 +0000 (Wed, 18 Dec 2019)" );
	script_cve_id( "CVE-2019-6467" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ISC BIND DoS Vulnerability (CVE-2019-6467) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_isc_bind_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "isc/bind/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "ISC BIND is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A programming error in the nxdomain-redirect feature can cause an assertion
  failure in query.c if the alternate namespace used by nxdomain-redirect is a descendant of a zone that is served
  locally.

  The most likely scenario where this might occur is if the server, in addition to performing NXDOMAIN redirection
  for recursive clients, is also serving a local copy of the root zone or using mirroring to provide the root zone,
  although other configurations are also possible." );
	script_tag( name: "impact", value: "An attacker who can deliberately trigger the condition on a server with a
  vulnerable configuration can cause BIND to exit, denying service to other clients." );
	script_tag( name: "affected", value: "BIND 9.12.0 to 9.12.4 and 9.14.0. Also affects all releases in the 9.13
  development branch." );
	script_tag( name: "solution", value: "Update to version 9.12.4-P1, 9.14.1 or later." );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/cve-2019-6467" );
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
if(version_in_range( version: version, test_version: "9.12.0", test_version2: "9.12.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.12.4-P1", install_path: location );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.13.0", test_version2: "9.14.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.14.1", install_path: location );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );

