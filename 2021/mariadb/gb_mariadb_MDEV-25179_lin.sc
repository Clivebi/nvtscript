CPE = "cpe:/a:mariadb:mariadb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145603" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-22 07:14:58 +0000 (Mon, 22 Mar 2021)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)" );
	script_cve_id( "CVE-2021-27928" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MariaDB RCE Vulnerability (MDEV-25179) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "MariaDB/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "MariaDB is prone to a remote code execution (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An untrusted search path leads to eval injection, in which a database SUPER
  user can execute OS commands after modifying wsrep_provider and wsrep_notify_cmd." );
	script_tag( name: "affected", value: "MariaDB versions 10.2.x, 10.3.x, 10.4.x and 10.5.x." );
	script_tag( name: "solution", value: "Update to version 10.2.37, 10.3.28, 10.4.18, 10.5.9 or later." );
	script_xref( name: "URL", value: "https://jira.mariadb.org/browse/MDEV-25179" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "10.2.0", test_version2: "10.2.36" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.2.37" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "10.3.0", test_version2: "10.3.27" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.3.28" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "10.4.0", test_version2: "10.4.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.4.18" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "10.5.0", test_version2: "10.5.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.5.9" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

