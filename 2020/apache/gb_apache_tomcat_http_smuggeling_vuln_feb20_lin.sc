CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108714" );
	script_version( "2021-07-22T02:00:50+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:00:50 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-02-25 06:37:31 +0000 (Tue, 25 Feb 2020)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_cve_id( "CVE-2019-17569" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache Tomcat HTTP Request Smuggling Vulnerability - Feb20 (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/tomcat/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Apache Tomcat is prone to a HTTP request smuggling vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Apache Tomcat 7.0.98 to 7.0.99, 8.5.48 to 8.5.50 and 9.0.28 to 9.0.30." );
	script_tag( name: "solution", value: "Update to version 7.0.100, 8.5.51, 9.0.31 or later." );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/r88def002c5c78534674ca67472e035099fbe088813d50062094a1390%40%3Cannounce.tomcat.apache.org%3E" );
	exit( 0 );
}
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
if(version_in_range( version: version, test_version: "7.0.98", test_version2: "7.0.99" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.100", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.5.48", test_version2: "8.5.50" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.5.51", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.0.28", test_version2: "9.0.30" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0.31", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

