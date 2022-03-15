CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811579" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-7546", "CVE-2017-7547" );
	script_bugtraq_id( 100275, 100278 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-08-17 12:50:23 +0530 (Thu, 17 Aug 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "PostgreSQL Multiple Vulnerabilities - August17 (Windows)" );
	script_tag( name: "summary", value: "PostgreSQL is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - libpq, and by extension any connection driver that utilizes libpq, ignores
    empty passwords and does not transmit them to the server.

  - User had access to see the options in pg_user_mappings even if the user did not
    have the USAGE permission on the associated foreign server." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  remote attacker to bypass security and obtain sensitive information." );
	script_tag( name: "affected", value: "PostgreSQL version 9.2.x before 9.2.22,
  9.3.x before 9.3.18, 9.4.x before 9.4.13, and 9.5.x before 9.5.8 and 9.6.x
  before 9.6.4." );
	script_tag( name: "solution", value: "Upgrade to version 9.2.22 or 9.3.18 or
  9.4.13 or 9.5.8 or 9.6.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.postgresql.org/about/news/1772/" );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/current/static/release-9-2-22.html" );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/current/static/release-9.5.8.html" );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/current/static/release-9.4.13.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if( IsMatchRegexp( vers, "^9\\.2" ) ){
	if(version_is_less( version: vers, test_version: "9.2.22" )){
		fix = "9.2.22";
	}
}
else {
	if( IsMatchRegexp( vers, "^9\\.3" ) ){
		if(version_is_less( version: vers, test_version: "9.3.18" )){
			fix = "9.3.18";
		}
	}
	else {
		if( IsMatchRegexp( vers, "^9\\.4" ) ){
			if(version_is_less( version: vers, test_version: "9.4.13" )){
				fix = "9.4.13";
			}
		}
		else {
			if( IsMatchRegexp( vers, "^9\\.5" ) ){
				if(version_is_less( version: vers, test_version: "9.5.8" )){
					fix = "9.5.8";
				}
			}
			else {
				if(IsMatchRegexp( vers, "^9\\.6" )){
					if(version_is_less( version: vers, test_version: "9.6.4" )){
						fix = "9.6.4";
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
