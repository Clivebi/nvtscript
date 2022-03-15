CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811236" );
	script_version( "2021-09-10T14:01:42+0000" );
	script_cve_id( "CVE-2017-9788" );
	script_bugtraq_id( 99569 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-10 14:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-07-17 16:02:23 +0530 (Mon, 17 Jul 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Apache HTTP Server 'mod_auth_digest' Multiple Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error in Apache
  'mod_auth_digest' which does not properly initialize memory used to process
  'Digest' type HTTP Authorization headers." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause the target service to crash. A remote user can obtain
  potentially sensitive information as well on the target system." );
	script_tag( name: "affected", value: "Apache HTTP Server 2.2.x before 2.2.34 and
  2.4.x before 2.4.27." );
	script_tag( name: "solution", value: "Update to Apache HTTP Server 2.2.34 or 2.4.27
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1038906" );
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
	if(version_is_less( version: vers, test_version: "2.4.27" )){
		fix = "2.4.27";
	}
}
else {
	if(IsMatchRegexp( vers, "^2\\.2" )){
		if(version_is_less( version: vers, test_version: "2.2.34" )){
			fix = "2.2.34";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

