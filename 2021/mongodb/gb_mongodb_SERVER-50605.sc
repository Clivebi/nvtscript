CPE = "cpe:/a:mongodb:mongodb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146380" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-26 05:01:41 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-03 19:49:00 +0000 (Tue, 03 Aug 2021)" );
	script_cve_id( "CVE-2021-20333" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MongoDB Log Spoofing Vulnerability (SERVER-50605)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_mongodb_detect.sc" );
	script_mandatory_keys( "mongodb/installed" );
	script_tag( name: "summary", value: "MongoDB is prone to a log spoofing vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Sending specially crafted commands to a MongoDB Server may result
  in artificial log entries being generated or for log entries to be split." );
	script_tag( name: "affected", value: "MongoDB version 3.6.x through 3.6.20, 4.0.x through 4.0.21 and
  4.2.x through 4.2.10." );
	script_tag( name: "solution", value: "Update to version 3.6.21, 4.0.22, 4.2.11 or later." );
	script_xref( name: "URL", value: "https://jira.mongodb.org/browse/SERVER-50605" );
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
if(version_in_range( version: version, test_version: "3.6.0", test_version2: "3.6.20" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.6.21" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.0.0", test_version2: "4.0.21" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.22" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.2.0", test_version2: "4.2.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.11" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

