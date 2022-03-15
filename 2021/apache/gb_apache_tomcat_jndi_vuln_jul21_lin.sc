CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146264" );
	script_version( "2021-08-24T06:00:58+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 06:00:58 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 05:12:04 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-26 17:00:00 +0000 (Mon, 26 Jul 2021)" );
	script_cve_id( "CVE-2021-30640" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache Tomcat JNDI Realm Authentication Weakness Vulnerability (Jul 2021) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/tomcat/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Apache Tomcat is prone to an authentication weakness
  vulnerability in the JNDI Realm." );
	script_tag( name: "insight", value: "Queries made by the JNDI Realm do not always correctly escape
  parameters. Parameter values could be sourced from user provided data (eg user names) as well as
  configuration data provided by an administrator. In limited circumstances it is possible for
  users to authenticate using variations of their user name and/or to bypass some of the protection
  provided by the LockOut Realm." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Apache Tomcat 7.0.x through 7.0.108, 8.5.x through 8.5.65,
  9.0.0.M1 through 9.0.45 and 10.0.0-M1 through 10.0.5." );
	script_tag( name: "solution", value: "Update to version 7.0.109, 8.5.66, 9.0.46, 10.0.6 or later." );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/r59f9ef03929d32120f91f4ea7e6e79edd5688d75d0a9b65fd26d1fe8%40%3Cannounce.tomcat.apache.org%3E" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.0.6" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.46" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.66" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.109" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "7.0.0", test_version2: "7.0.108" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.109", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.5.0", test_version2: "8.5.65" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.5.66", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(( revcomp( a: version, b: "9.0.0.M1" ) >= 0 ) && ( revcomp( a: version, b: "9.0.45" ) <= 0 )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0.46", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(( revcomp( a: version, b: "10.0.0.M1" ) >= 0 ) && ( revcomp( a: version, b: "10.0.5" ) <= 0 )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.0.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

