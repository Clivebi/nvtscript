CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146722" );
	script_version( "2021-10-04T08:02:33+0000" );
	script_tag( name: "last_modification", value: "2021-10-04 08:02:33 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "creation_date", value: "2021-09-17 09:04:02 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-28 19:02:00 +0000 (Tue, 28 Sep 2021)" );
	script_cve_id( "CVE-2021-41079" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache Tomcat DoS Vulnerability (Sep 2021) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/tomcat/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Apache Tomcat is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "insight", value: "When Tomcat was configured to use NIO+OpenSSL or NIO2+OpenSSL
  for TLS, a specially crafted packet could be used to trigger an infinite loop resulting in a
  denial of service." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Apache Tomcat 8.5.0 through 8.5.63, 9.0.0-M1 through 9.0.43 and
  10.0.0-M1 through 10.0.2." );
	script_tag( name: "solution", value: "Update to version 8.5.64, 9.0.44, 10.0.4 or later." );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/rccdef0349fdf4fb73a4e4403095446d7fe6264e0a58e2df5c6799434%40%3Cannounce.tomcat.apache.org%3E" );
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
if(version_in_range( version: version, test_version: "8.5.0", test_version2: "8.5.63" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.5.64", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(( revcomp( a: version, b: "9.0.0.M1" ) >= 0 ) && ( revcomp( a: version, b: "9.0.43" ) <= 0 )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0.44", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(( revcomp( a: version, b: "10.0.0.M1" ) >= 0 ) && ( revcomp( a: version, b: "10.0.2" ) <= 0 )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.0.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
