CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812312" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-15099" );
	script_bugtraq_id( 101781 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-28 10:29:00 +0000 (Tue, 28 Aug 2018)" );
	script_tag( name: "creation_date", value: "2017-12-04 16:46:13 +0530 (Mon, 04 Dec 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "PostgreSQL Security Bypass Vulnerability-Dec17 (Linux)" );
	script_tag( name: "summary", value: "PostgreSQL is prone to a security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as commands 'INSERT .. ON CONFLICT DO UPDATE'
  disclose table contents that the invoker lacks privilege to read." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  authenticated users to bypass access controls on the target system." );
	script_tag( name: "affected", value: "PostgreSQL version 9.5.x before 9.5.10, 9.6.x
  before 9.6.6 and 10.x before 10.1." );
	script_tag( name: "solution", value: "Upgrade to PostgreSQL version 10.1 or 9.6.6
  or 9.5.10 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.postgresql.org/about/news/1801" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "postgresql_detect.sc", "secpod_postgresql_detect_lin.sc", "secpod_postgresql_detect_win.sc", "os_detection.sc" );
	script_mandatory_keys( "postgresql/detected", "Host/runs_unixoide" );
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
if( IsMatchRegexp( vers, "^9\\.5" ) ){
	if(version_is_less( version: vers, test_version: "9.5.10" )){
		fix = "9.5.10";
	}
}
else {
	if( IsMatchRegexp( vers, "^9\\.6" ) ){
		if(version_is_less( version: vers, test_version: "9.6.6" )){
			fix = "9.6.6";
		}
	}
	else {
		if(IsMatchRegexp( vers, "^10\\." )){
			if(version_is_less( version: vers, test_version: "10.1" )){
				fix = "10.1";
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

