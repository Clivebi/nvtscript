CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812847" );
	script_version( "2021-06-15T02:00:29+0000" );
	script_cve_id( "CVE-2018-1303" );
	script_bugtraq_id( 103522 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-04 15:09:39 +0530 (Wed, 04 Apr 2018)" );
	script_name( "Apache HTTP Server Denial of Service Vulnerability-02 Apr18 (Windows)" );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the Apache HTTP Server
  fails to sanitize against a specially crafted HTTP request header." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to crash the Apache HTTP Server resulting in denial of service condition." );
	script_tag( name: "affected", value: "Apache HTTP Server versions 2.4.6, 2.4.7,
  2.4.9, 2.4.10, 2.4.12, 2.4.16 through 2.4.18, 2.4.20, 2.4.23, and 2.4.25 through
  2.4.29." );
	script_tag( name: "solution", value: "Update to version 2.4.30 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://httpd.apache.org/security/vulnerabilities_24.html" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/http_server/detected", "Host/runs_windows" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
not_affected = make_list( "2.4.8",
	 "2.4.11",
	 "2.4.13",
	 "2.4.14",
	 "2.4.15",
	 "2.4.19",
	 "2.4.21",
	 "2.4.22",
	 "2.4.24" );
if(version_in_range( version: vers, test_version: "2.4.6", test_version2: "2.4.29" )){
	for version in not_affected {
		if(vers == version){
			exit( 99 );
		}
	}
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.4.30", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

