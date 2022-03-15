CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142264" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-04-16 07:09:53 +0000 (Tue, 16 Apr 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-28 21:29:00 +0000 (Tue, 28 May 2019)" );
	script_cve_id( "CVE-2019-0199" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache Tomcat DoS Vulnerability - March19 (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/tomcat/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Apache Tomcat is prone to a denial of service vulnerability in the HTTP/2
  implementation." );
	script_tag( name: "insight", value: "The HTTP/2 implementation accepts streams with excessive numbers of SETTINGS
  frames and also permitts clients to keep streams open without reading/writing request/response data. By keeping
  streams open for requests that utilises the Servlet API's blocking I/O, clients are able to cause server-side
  threads to block eventually leading to thread exhaustion and a DoS." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Apache Tomcat 8.5.0 to 8.5.37 and 9.0.0.M1 to 9.0.14." );
	script_tag( name: "solution", value: "Update to version 8.5.38, 9.0.16 or later." );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-9.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-8.html" );
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
path = infos["location"];
if(version_in_range( version: version, test_version: "8.5.0", test_version2: "8.5.37" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.5.38", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(( revcomp( a: version, b: "9.0.0.M1" ) >= 0 ) && ( revcomp( a: version, b: "9.0.14" ) <= 0 )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0.16", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

