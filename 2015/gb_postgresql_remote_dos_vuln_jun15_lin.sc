CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805805" );
	script_version( "2020-01-28T13:26:39+0000" );
	script_cve_id( "CVE-2015-3165" );
	script_bugtraq_id( 74787 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-01-28 13:26:39 +0000 (Tue, 28 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-06-24 15:36:26 +0530 (Wed, 24 Jun 2015)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "PostgreSQL Remote Denial Of Service Vulnerability June15 (Linux)" );
	script_tag( name: "summary", value: "This host is running PostgreSQL and is
  prone to remote denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is triggered when a timeout interrupt
  is fired partway through the session shutdown sequence." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  remote attacker to crash the program." );
	script_tag( name: "affected", value: "PostgreSQL version before 9.0.20, 9.1.x
  before 9.1.16, 9.2.x before 9.2.11, 9.3.x before 9.3.7, and 9.4.x before 9.4.2." );
	script_tag( name: "solution", value: "Upgrade to version 9.0.20, 9.1.16, 9.2.11,
  9.3.7, 9.4.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.postgresql.org/about/news/1587" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "9.0.20" ) || version_in_range( version: vers, test_version: "9.1", test_version2: "9.1.15" ) || version_in_range( version: vers, test_version: "9.2", test_version2: "9.2.10" ) || version_in_range( version: vers, test_version: "9.3", test_version2: "9.3.6" ) || version_in_range( version: vers, test_version: "9.4", test_version2: "9.4.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

