CPE = "cpe:/a:mongodb:mongodb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144948" );
	script_version( "2021-08-12T09:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-12-02 05:14:51 +0000 (Wed, 02 Dec 2020)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-02 21:48:00 +0000 (Wed, 02 Dec 2020)" );
	script_cve_id( "CVE-2020-7928" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MongoDB 3.6 < 3.6.20, 4.0 < 4.0.20, 4.2 < 4.2.9, 4.4 < 4.4.1 Read Overrun Vulnerability - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_mongodb_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mongodb/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "MongoDB is prone to a read overrun vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A user authorized to perform database queries may trigger a read overrun and
  access arbitrary memory by issuing specially crafted queries." );
	script_tag( name: "affected", value: "MongoDB versions 3.6 prior to 3.6.20, 4.0 prior to 4.0.20, 4.2 prior to
  4.2.9 and 4.4 prior to 4.4.1." );
	script_tag( name: "solution", value: "Update to version 3.6.20, 4.0.20, 4.2.9, 4.4.1 or later." );
	script_xref( name: "URL", value: "https://jira.mongodb.org/browse/SERVER-49404" );
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
if(version_in_range( version: version, test_version: "3.6", test_version2: "3.6.19" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.6.20" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.0", test_version2: "4.0.19" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.20" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.2", test_version2: "4.2.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.9" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version == "4.4.0"){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.4.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
