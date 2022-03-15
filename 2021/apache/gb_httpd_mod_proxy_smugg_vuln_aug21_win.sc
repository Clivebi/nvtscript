if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117616" );
	script_version( "2021-09-17T11:59:51+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 11:59:51 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-08-09 08:04:51 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-24 12:45:00 +0000 (Tue, 24 Aug 2021)" );
	script_cve_id( "CVE-2021-33193" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache HTTP Server 2.4.17 < 2.4.49 'mod_proxy' HTTP/2 Request Smuggling Vulnerability - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/http_server/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to an HTTP/2 request smuggling
  vulnerability in the 'mod_proxy' module." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Apache's mod_proxy allows spaces in the :method of HTTP/2
  requests, enabling request line injection. If the back-end server tolerates trailing junk in the
  request line, this lets an attacker to bypass block rules." );
	script_tag( name: "affected", value: "Apache HTTP Server version 2.4.17 through 2.4.48 running the
  mod_proxy module together with an enabled HTTP/2 protocol." );
	script_tag( name: "solution", value: "Update to version 2.4.49 or later." );
	script_xref( name: "URL", value: "https://portswigger.net/research/http2" );
	script_xref( name: "URL", value: "https://github.com/apache/httpd/commit/ecebcc035ccd8d0e2984fe41420d9e944f456b3c" );
	script_xref( name: "URL", value: "https://httpd.apache.org/security/vulnerabilities_24.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/a:apache:http_server";
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "2.4.17", test_version2: "2.4.48" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.4.49", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

