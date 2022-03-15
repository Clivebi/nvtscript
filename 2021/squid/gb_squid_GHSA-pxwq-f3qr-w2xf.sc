CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146027" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-05-28 03:31:55 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-16 11:15:00 +0000 (Fri, 16 Jul 2021)" );
	script_cve_id( "CVE-2021-31806", "CVE-2021-31807", "CVE-2021-31808" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Squid 2.5.STABLE2 < 4.15, 5.0.1 < 5.0.6 Multiple DoS Vulnerabilities (SQUID-2021:4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "Squid is prone to multiple denial of service (DoS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-31806: Due to an incorrect input validation bug Squid is vulnerable to a DoS attack
    against all clients using the proxy.

  - CVE-2021-31807: Due to an incorrect memory management bug Squid is vulnerable to a DoS attack
    against all clients using the proxy.

  - CVE-2021-31808: Due to an integer overflow bug Squid is vulnerable to a DoS attack against all
    clients using the proxy." );
	script_tag( name: "affected", value: "Squid version 2.5.STABLE2 through 2.7.STABLE9, 3.0 through 4.14
  and 5.0.1 through 5.0.5." );
	script_tag( name: "solution", value: "Update to version 4.15, 5.0.6 or later." );
	script_xref( name: "URL", value: "https://github.com/squid-cache/squid/security/advisories/GHSA-pxwq-f3qr-w2xf" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(IsMatchRegexp( version, "^2\\.[567]" ) || version_in_range( version: version, test_version: "3.0", test_version2: "4.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.15", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.1", test_version2: "5.0.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

