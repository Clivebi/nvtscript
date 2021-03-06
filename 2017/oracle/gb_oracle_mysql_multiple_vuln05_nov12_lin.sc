CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812194" );
	script_version( "2019-10-17T12:29:45+0000" );
	script_cve_id( "CVE-2012-3156" );
	script_bugtraq_id( 56013 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2019-10-17 12:29:45 +0000 (Thu, 17 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-11-23 14:42:41 +0530 (Thu, 23 Nov 2017)" );
	script_name( "Oracle MySQL Server Multiple Vulnerabilities-05 Nov12 (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51008/" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/51008" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html" );
	script_xref( name: "URL", value: "https://support.oracle.com/rs?type=doc&id=1475188.1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed", "Host/runs_unixoide" );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to disclose potentially sensitive information and manipulate certain data." );
	script_tag( name: "affected", value: "Oracle MySQL version 5.5.x to 5.5.25 on Linux." );
	script_tag( name: "insight", value: "The flaw is due to unspecified error in
  MySQL server component vectors server." );
	script_tag( name: "solution", value: "Apply the patch from the referenced vendor advisory
  or upgrade to the latest version." );
	script_tag( name: "summary", value: "The host is running Oracle MySQL server
  and is prone to unspecified vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
vers = eregmatch( pattern: "([0-9.a-z]+)", string: vers );
if(vers[1]){
	if(version_in_range( version: vers[1], test_version: "5.5.0", test_version2: "5.5.25" )){
		report = report_fixed_ver( installed_version: vers[1], fixed_version: "Apply the patch", install_path: path );
		security_message( data: report, port: port );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

