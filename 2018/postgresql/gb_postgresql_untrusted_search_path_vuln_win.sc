if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112398" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2007-2138" );
	script_bugtraq_id( 23618 );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-10-23 13:37:11 +0200 (Tue, 23 Oct 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "PostgreSQL < 7.3.19, 7.4.x < 7.4.17, 8.0.x < 8.0.13, 8.1.x < 8.1.9, and 8.2.x < 8.2.4 Untrusted Search Path Vulnerability - Windows" );
	script_tag( name: "summary", value: "PostgreSQL is prone to an untrusted search path vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Untrusted search path vulnerability in PostgreSQL allows remote authenticated users,
  when permitted to call a SECURITY DEFINER function, to gain the privileges of the function owner, related to 'search_path settings'." );
	script_tag( name: "affected", value: "PostgreSQL versions before 7.3.19, 7.4.x before 7.4.17, 8.0.x before 8.0.13,
  8.1.x before 8.1.9, and 8.2.x before 8.2.4." );
	script_tag( name: "solution", value: "Update to version 7.3.19, 7.4.17, 8.0.13, 8.1.9, or 8.2.4 respectively." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.securitytracker.com/id?1017974" );
	script_xref( name: "URL", value: "https://exchange.xforce.ibmcloud.com/vulnerabilities/33842" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "postgresql_detect.sc", "secpod_postgresql_detect_lin.sc", "secpod_postgresql_detect_win.sc", "os_detection.sc" );
	script_mandatory_keys( "postgresql/detected", "Host/runs_windows" );
	exit( 0 );
}
CPE = "cpe:/a:postgresql:postgresql";
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( version_is_less( version: vers, test_version: "7.3.19" ) ){
	fix = "7.3.19";
}
else {
	if( IsMatchRegexp( vers, "^7\\.4\\." ) ){
		if(version_is_less( version: vers, test_version: "7.4.17" )){
			fix = "7.4.17";
		}
	}
	else {
		if( IsMatchRegexp( vers, "^8\\.0\\." ) ){
			if(version_is_less( version: vers, test_version: "8.0.13" )){
				fix = "8.0.13";
			}
		}
		else {
			if( IsMatchRegexp( vers, "^8\\.1\\." ) ){
				if(version_is_less( version: vers, test_version: "8.1.9" )){
					fix = "8.1.9";
				}
			}
			else {
				if(IsMatchRegexp( vers, "^8\\.2\\." )){
					if(version_is_less( version: vers, test_version: "8.2.4" )){
						fix = "8.2.4";
					}
				}
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

