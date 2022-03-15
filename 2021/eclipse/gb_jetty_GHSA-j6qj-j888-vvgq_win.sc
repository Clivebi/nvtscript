CPE = "cpe:/a:eclipse:jetty";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117490" );
	script_version( "2021-08-27T11:01:07+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 11:01:07 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-02 02:47:24 +0000 (Tue, 02 Mar 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-11 17:15:00 +0000 (Sun, 11 Jul 2021)" );
	script_cve_id( "CVE-2021-28163" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Eclipse Jetty Information Disclosure Vulnerability (GHSA-j6qj-j888-vvgq) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_jetty_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "jetty/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Eclipse Jetty is prone to an information disclosure
  vulnerability." );
	script_tag( name: "impact", value: "If the ${jetty.base} directory or the ${jetty.base}/webapps
  directory is a symlink (soft link in Linux), the contents of the ${jetty.base}/webapps directory
  may be deployed as a static web application, exposing the content of the directory for download." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Eclipse Jetty version 9.4.32 through 9.4.38, 10.0.0.beta2
  through 10.0.1 and 11.0.0.beta2 through 11.0.1." );
	script_tag( name: "solution", value: "Update to version 9.4.39, 10.0.2, 11.0.2 or later." );
	script_xref( name: "URL", value: "https://github.com/eclipse/jetty.project/security/advisories/GHSA-j6qj-j888-vvgq" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "9.4.32", test_version2: "9.4.38" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.4.39", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "10.0.0", test_version2: "10.0.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.0.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "11.0.0", test_version2: "11.0.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.0.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

