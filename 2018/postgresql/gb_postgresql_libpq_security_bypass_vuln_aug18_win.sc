CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813751" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-10915" );
	script_bugtraq_id( 105054 );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-17 19:15:00 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-13 12:44:42 +0530 (Mon, 13 Aug 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "PostgreSQL 'libpq' Security Bypass Vulnerability (Aug 2018) - Windows" );
	script_tag( name: "summary", value: "PostgreSQL is prone to a security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an internal issue in
  the 'libpq' the client connection API for PostgreSQL where it did not reset
  all of its connection state variables when attempting to reconnect. In
  particular, the state variable that determined whether or not a password is
  needed for a connection would not be reset." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to bypass client-side connection security features and obtain access to higher
  privileged connections or potentially cause other possible impact." );
	script_tag( name: "affected", value: "PostgreSQL versions before 10.5, 9.6.10,
  9.5.14, 9.4.19 and 9.3.24." );
	script_tag( name: "solution", value: "Update to version 10.5 or 9.6.10
  or 9.5.14 or 9.4.19 or 9.3.24 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.postgresql.org/about/news/1878" );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/10/static/release-10-5.html#id-1.11.6.5.5" );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/10/static/release-9-6-10.html#id-1.11.6.11.5" );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/10/static/release-9-5-14.html#id-1.11.6.22.5" );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/10/static/release-9-4-19.html#id-1.11.6.37.5" );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/10/static/release-9-3-24.html#id-1.11.6.57.6" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "postgresql_detect.sc", "secpod_postgresql_detect_lin.sc", "secpod_postgresql_detect_win.sc", "os_detection.sc" );
	script_mandatory_keys( "postgresql/detected", "Host/runs_windows" );
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
loc = infos["location"];
if( IsMatchRegexp( vers, "^9\\.3\\." ) ){
	if(version_is_less( version: vers, test_version: "9.3.24" )){
		fix = "9.3.24";
	}
}
else {
	if( IsMatchRegexp( vers, "^9\\.4\\." ) ){
		if(version_is_less( version: vers, test_version: "9.4.19" )){
			fix = "9.4.19";
		}
	}
	else {
		if( IsMatchRegexp( vers, "^9\\.5\\." ) ){
			if(version_is_less( version: vers, test_version: "9.5.14" )){
				fix = "9.5.14";
			}
		}
		else {
			if( IsMatchRegexp( vers, "^9\\.6\\." ) ){
				if(version_is_less( version: vers, test_version: "9.6.10" )){
					fix = "9.6.10";
				}
			}
			else {
				if(IsMatchRegexp( vers, "^10\\." )){
					if(version_is_less( version: vers, test_version: "10.5" )){
						fix = "10.5";
					}
				}
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

