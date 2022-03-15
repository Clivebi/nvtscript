if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112429" );
	script_version( "2021-06-07T11:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-07 11:00:20 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-14 15:00:11 +0100 (Wed, 14 Nov 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:36:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-16850" );
	script_name( "PostgreSQL < 10.6, 11.x < 11.1 SQL Injection Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "postgresql_detect.sc", "secpod_postgresql_detect_lin.sc", "secpod_postgresql_detect_win.sc", "os_detection.sc" );
	script_mandatory_keys( "postgresql/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "PostgreSQL is prone to an SQL injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A SQL Injection flaw has been discovered in PostgreSQL server in the way
  triggers that enable transition relations are dumped. The transition relation name is not correctly quoted
  and it may allow an attacker with CREATE privilege on some non-temporary schema or TRIGGER privilege on some
  table to create a malicious trigger that, when dumped and restored, would result in additional SQL statements being executed." );
	script_tag( name: "affected", value: "PostgreSQL before versions 10.6 and 11.1." );
	script_tag( name: "solution", value: "Update to version 10.6 or 11.1 respectively." );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-16850" );
	script_xref( name: "URL", value: "https://www.postgresql.org/about/news/1905/" );
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
if(version_is_less( version: version, test_version: "10.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.6", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "11.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.1", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

