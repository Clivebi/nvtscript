CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810991" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-7484", "CVE-2017-7486" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2017-05-15 16:07:12 +0530 (Mon, 15 May 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "PostgreSQL Multiple Information Disclosure Vulnerabilities - May17 (Windows)" );
	script_tag( name: "summary", value: "PostgreSQL is prone to multiple information disclosure vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Some selectivity estimation functions did not check user privileges before
    providing information from pg_statistic, possibly leaking information.

  - An error in 'pg_user_mappings' view." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  unprivileged attacker to steal some information." );
	script_tag( name: "affected", value: "PostgreSQL version before 9.2.21, 9.3.x
  before 9.3.17, 9.4.x before 9.4.12, 9.5.x before 9.5.7, and 9.6.x before 9.6.3." );
	script_tag( name: "solution", value: "Upgrade to PostgreSQL version 9.2.21 or
  9.3.17 or 9.4.12 or 9.5.7 or 9.6.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.postgresql.org/about/news/1746" );
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
if( IsMatchRegexp( vers, "^9\\.3" ) ){
	if(version_is_less( version: vers, test_version: "9.3.17" )){
		fix = "9.3.17";
	}
}
else {
	if( IsMatchRegexp( vers, "^9\\.4" ) ){
		if(version_is_less( version: vers, test_version: "9.4.12" )){
			fix = "9.4.12";
		}
	}
	else {
		if( IsMatchRegexp( vers, "^9\\.5" ) ){
			if(version_is_less( version: vers, test_version: "9.5.7" )){
				fix = "9.5.7";
			}
		}
		else {
			if( IsMatchRegexp( vers, "^9\\.6" ) ){
				if(version_is_less( version: vers, test_version: "9.6.3" )){
					fix = "9.6.3";
				}
			}
			else {
				if(version_is_less( version: vers, test_version: "9.2.21" )){
					fix = "9.2.21";
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

