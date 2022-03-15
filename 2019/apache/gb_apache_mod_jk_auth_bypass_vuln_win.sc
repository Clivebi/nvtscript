CPE = "cpe:/a:apache:mod_jk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141820" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-03 11:33:11 +0700 (Thu, 03 Jan 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-15 16:31:00 +0000 (Mon, 15 Apr 2019)" );
	script_cve_id( "CVE-2018-11759" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache Tomcat JK Connector (mod_jk) < 1.2.46 Authentication Bypass Vulnerability - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_mod_jk_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/mod_jk/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Apache Tomcat JK Connector (mod_jk) is prone to an
  authentication bypass vulnerability." );
	script_tag( name: "insight", value: "The Apache Web Server (httpd) specific code that normalised the
  requested path before matching it to the URI-worker map in Apache Tomcat JK (mod_jk) Connector
  1.2.0 to 1.2.44 did not handle some edge cases correctly. If only a sub-set of the URLs supported
  by Tomcat were exposed via httpd, then it was possible for a specially constructed request to
  expose application functionality through the reverse proxy that was not intended for clients
  accessing the application via the reverse proxy. It was also possible in some configurations for a
  specially constructed request to bypass the access controls configured in httpd. While there is
  some overlap between this issue and CVE-2018-1323, they are not identical." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Apache Tomcat JK Connector (mod_jk) version 1.2.0 through 1.2.44." );
	script_tag( name: "solution", value: "Update to version 1.2.46 or later." );
	script_xref( name: "URL", value: "https://mail-archives.apache.org/mod_mbox/www-announce/201810.mbox/%3C16a616e5-5245-f26a-a5a4-2752b2826703%40apache.org%3E" );
	script_xref( name: "URL", value: "https://www.immunit.ch/en/blog/2018/11/02/cve-2018-11759-apache-mod_jk-access-control-bypass/" );
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
path = infos["location"];
if(version_in_range( version: version, test_version: "1.2.0", test_version2: "1.2.44" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.46", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

