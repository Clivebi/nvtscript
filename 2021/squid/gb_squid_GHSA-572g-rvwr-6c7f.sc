CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146026" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-05-28 03:24:02 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 09:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_cve_id( "CVE-2021-33620" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Squid < 4.15, 5.0.x < 5.0.6 DoS Vulnerability (SQUID-2021:5)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "Squid is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Due to an input validation bug Squid is vulnerable to a DoS
  against all clients using the proxy.

  This problem allows a remote server to perform a DoS when delivering HTTP Response messages. The
  issue trigger is a header which can be expected to exist in HTTP traffic without any malicious
  intent by the server." );
	script_tag( name: "affected", value: "Squid versions prior to 4.15 and 5.0.0 through 5.0.5." );
	script_tag( name: "solution", value: "Update to version 4.15, 5.0.6 or later." );
	script_xref( name: "URL", value: "https://github.com/squid-cache/squid/security/advisories/GHSA-572g-rvwr-6c7f" );
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
if(version_is_less( version: version, test_version: "4.15" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.15", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

