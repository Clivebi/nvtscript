CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807085" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_cve_id( "CVE-2016-0773", "CVE-2016-0766" );
	script_bugtraq_id( 83184 );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
	script_tag( name: "creation_date", value: "2016-03-10 19:31:43 +0530 (Thu, 10 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "PostgreSQL Multiple Vulnerabilities - Mar15 (Windows)" );
	script_tag( name: "summary", value: "This host is running PostgreSQL and is
  prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to the postgreSQL
  incorrectly handle certain regular expressions and  certain configuration
  settings (GUCS) for users of PL/Java." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  remote attacker to escalate privileges and to cause denial of service
  conditions." );
	script_tag( name: "affected", value: "PostgreSQL version before 9.1.20, 9.2.x
  before 9.2.15, 9.3.x before 9.3.11, 9.4.x before 9.4.6, and 9.5.x before
  9.5.1." );
	script_tag( name: "solution", value: "Upgrade to version 9.1.20 or 9.2.15 or
  9.3.11 or 9.4.6 or 9.5.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/USN-2894-1" );
	script_xref( name: "URL", value: "http://www.postgresql.org/about/news/1644" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if( version_is_less( version: vers, test_version: "9.1.20" ) ){
	fix = "9.1.20";
	VULN = TRUE;
}
else {
	if( IsMatchRegexp( vers, "^9\\.2" ) ){
		if(version_is_less( version: vers, test_version: "9.2.15" )){
			fix = "9.2.15";
			VULN = TRUE;
		}
	}
	else {
		if( IsMatchRegexp( vers, "^9\\.3" ) ){
			if(version_is_less( version: vers, test_version: "9.3.11" )){
				fix = "9.3.11";
				VULN = TRUE;
			}
		}
		else {
			if( IsMatchRegexp( vers, "^9\\.4" ) ){
				if(version_is_less( version: vers, test_version: "9.4.6" )){
					fix = "9.4.6";
					VULN = TRUE;
				}
			}
			else {
				if(IsMatchRegexp( vers, "^9\\.5" )){
					if(version_is_less( version: vers, test_version: "9.5.1" )){
						fix = "9.5.1";
						VULN = TRUE;
					}
				}
			}
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: loc );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

