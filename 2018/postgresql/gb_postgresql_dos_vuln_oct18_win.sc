if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113283" );
	script_version( "2020-01-28T13:26:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-28 13:26:39 +0000 (Tue, 28 Jan 2020)" );
	script_tag( name: "creation_date", value: "2018-10-30 15:32:24 +0200 (Tue, 30 Oct 2018)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2007-6600", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-4769", "CVE-2007-6601" );
	script_bugtraq_id( 27163 );
	script_name( "PostgreSQL 7.4 < 7.4.19, 8.0 < 8.0.15, 8.1 < 8.1.11, 8.2 < 8.2.6 Multiple Vulnerabilities (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "postgresql_detect.sc", "secpod_postgresql_detect_lin.sc", "secpod_postgresql_detect_win.sc", "os_detection.sc" );
	script_mandatory_keys( "postgresql/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "PostgreSQL is prone to multiple Privilege Escalation and Denial of Service (DoS)
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "PostgreSQL 7.4.0 through 7.4.18, 8.0.0 through 8.0.14, 8.1.0 through 8.1.10
  and 8.2.0 through 8.2.5." );
	script_tag( name: "solution", value: "Update to version 7.4.19, 8.0.15, 8.1.11 or 8.2.6 respectively." );
	script_xref( name: "URL", value: "https://www.securityfocus.com/archive/1/485864/100/0/threaded" );
	exit( 0 );
}
CPE = "cpe:/a:postgresql:postgresql";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "7.4.0", test_version2: "7.4.18" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.4.19", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0.0", test_version2: "8.0.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.15", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.1.0", test_version2: "8.1.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.1.11", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.2.0", test_version2: "8.2.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.2.6", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

