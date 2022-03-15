CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811217" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_cve_id( "CVE-2017-7659" );
	script_bugtraq_id( 99132 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-06-21 17:56:43 +0530 (Wed, 21 Jun 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Apache HTTP Server 'mod_http2' null pointer dereference DoS Vulnerability (Windows)" );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to a denial-of-service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as a maliciously constructed
  HTTP/2 request could cause mod_http2 to dereference a NULL pointer and crash
  the server process." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial-of-service condition." );
	script_tag( name: "affected", value: "Apache HTTP Server version 2.4.25." );
	script_tag( name: "solution", value: "Update to Apache HTTP Server 2.4.26 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2017/q2/504" );
	script_xref( name: "URL", value: "http://httpd.apache.org/security/vulnerabilities_24.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/http_server/detected", "Host/runs_windows" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^2\\.4" )){
	if(version_is_equal( version: vers, test_version: "2.4.25" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "2.4.26", install_path: path );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

