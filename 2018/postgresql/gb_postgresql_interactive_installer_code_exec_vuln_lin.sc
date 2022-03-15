CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814222" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2016-7048" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-12 20:12:00 +0000 (Fri, 12 Oct 2018)" );
	script_tag( name: "creation_date", value: "2018-09-28 11:44:36 +0530 (Fri, 28 Sep 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "PostgreSQL 'Interactive Installer' Arbitrary Code Execution Vulnerability - Linux" );
	script_tag( name: "summary", value: "PostgreSQL is prone to an arbitrary code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists as interactive installer
  downloads software over plain HTTP and then executes it." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "PostgreSQL versions 9.3.x prior to 9.3.15,
  9.4.x prior to 9.4.10 and 9.5.x prior to 9.5.5." );
	script_tag( name: "solution", value: "Update to version 9.3.15 or
  9.4.10 or 9.5.5 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://access.redhat.com/security/cve/cve-2016-7048" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if( IsMatchRegexp( vers, "^9\\.5\\." ) ){
	if(version_is_less( version: vers, test_version: "9.5.5" )){
		fix = "9.5.5";
	}
}
else {
	if( IsMatchRegexp( vers, "^9\\.4\\." ) ){
		if(version_is_less( version: vers, test_version: "9.4.10" )){
			fix = "9.4.10";
		}
	}
	else {
		if(IsMatchRegexp( vers, "^9\\.3" )){
			if(version_is_less( version: vers, test_version: "9.3.15" )){
				fix = "9.3.15";
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

