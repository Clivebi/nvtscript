CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811215" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_cve_id( "CVE-2017-7668" );
	script_bugtraq_id( 99137 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-06-21 18:06:43 +0530 (Wed, 21 Jun 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Apache HTTP Server Denial-Of-Service Vulnerability June17 (Windows)" );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to a denial-of-service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in the
  token list parsing, which allows ap_find_token() to search past the end of its
  input string. By maliciously crafting a sequence of request headers, an
  attacker may be able to cause a segmentation fault, or to force
  ap_find_token() to return an incorrect value." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial-of-service condition." );
	script_tag( name: "affected", value: "Apache HTTP Server versions 2.2.32, 2.4.24
  and 2.4.25." );
	script_tag( name: "solution", value: "Update to Apache HTTP Server 2.2.33 or 2.4.26
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2017/q2/510" );
	script_xref( name: "URL", value: "http://httpd.apache.org/security/vulnerabilities_22.html" );
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
if( IsMatchRegexp( vers, "^2\\.4" ) ){
	if(version_is_equal( version: vers, test_version: "2.4.25" ) || version_is_equal( version: vers, test_version: "2.4.24" )){
		fix = "2.4.26";
	}
}
else {
	if(IsMatchRegexp( vers, "^2\\.2" )){
		if(version_is_equal( version: vers, test_version: "2.2.32" )){
			fix = "2.2.33";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

