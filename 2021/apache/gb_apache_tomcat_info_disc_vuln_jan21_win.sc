CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117158" );
	script_version( "2021-08-24T06:00:58+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 06:00:58 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-15 13:01:06 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_cve_id( "CVE-2021-24122" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache Tomcat Information Disclosure Vulnerability - Jan21 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/tomcat/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Apache Tomcat is prone to an information disclosure vulnerability." );
	script_tag( name: "insight", value: "When serving resources from a network location using the NTFS file system
  it was possible to bypass security constraints and/or view the source code for JSPs in some configurations.
  The root cause was the unexpected behaviour of the JRE API File.getCanonicalPath() which in turn was caused
  by the inconsistent behaviour of the Windows API (FindFirstFileW) in some circumstances." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Apache Tomcat 7.0.0 to 7.0.106, 8.5.0 to 8.5.59, 9.0.0.M1 to 9.0.39 and 10.0.0-M1 to 10.0.0-M9." );
	script_tag( name: "solution", value: "Update to version 7.0.107, 8.5.60, 9.0.40, 10.0.0-M10 or later." );
	script_xref( name: "URL", value: "https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.0.0-M10" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.40" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.60" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.107" );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/rce5ac9a40173651d540babce59f6f3825f12c6d4e886ba00823b11e5%40%3Cannounce.tomcat.apache.org%3E" );
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
if(version_in_range( version: version, test_version: "7.0.0", test_version2: "7.0.106" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.107", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.5.0", test_version2: "8.5.59" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.5.60", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(( revcomp( a: version, b: "9.0.0.M1" ) >= 0 ) && ( revcomp( a: version, b: "9.0.39" ) <= 0 )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0.40", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(( revcomp( a: version, b: "10.0.0.M1" ) >= 0 ) && ( revcomp( a: version, b: "10.0.0.M9" ) <= 0 )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.0.0-M10", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

