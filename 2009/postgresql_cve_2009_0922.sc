CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100157" );
	script_version( "2020-01-28T13:26:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-28 13:26:39 +0000 (Tue, 28 Jan 2020)" );
	script_tag( name: "creation_date", value: "2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)" );
	script_bugtraq_id( 34090 );
	script_cve_id( "CVE-2009-0922" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_name( "PostgreSQL Conversion Encoding Remote Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "postgresql_detect.sc", "secpod_postgresql_detect_lin.sc", "secpod_postgresql_detect_win.sc" );
	script_mandatory_keys( "postgresql/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34090" );
	script_tag( name: "summary", value: "PostgreSQL is prone to a remote denial-of-service vulnerability." );
	script_tag( name: "impact", value: "Exploiting this issue may allow attackers to terminate connections
  to the PostgreSQL server, denying service to legitimate users." );
	script_tag( name: "solution", value: "Updates are available. Update to newer Version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
loc = infos["location"];
if(version_in_range( version: vers, test_version: "8.3", test_version2: "8.3.6" ) || version_in_range( version: vers, test_version: "8.2", test_version2: "8.2.6" ) || version_in_range( version: vers, test_version: "8.1", test_version2: "8.1.11" ) || version_in_range( version: vers, test_version: "8.0", test_version2: "8.0.17" ) || version_in_range( version: vers, test_version: "7.4", test_version2: "7.4.19" ) || version_in_range( version: vers, test_version: "7.3", test_version2: "7.3.21" ) || version_in_range( version: vers, test_version: "7.2", test_version2: "7.2.7" ) || version_in_range( version: vers, test_version: "7.1", test_version2: "7.1.3" ) || version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.3" ) || version_in_range( version: vers, test_version: "6.5", test_version2: "6.5.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

