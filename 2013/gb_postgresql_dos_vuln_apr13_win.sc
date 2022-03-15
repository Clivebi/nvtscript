CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803473" );
	script_version( "2020-01-28T13:26:39+0000" );
	script_cve_id( "CVE-2013-1899" );
	script_bugtraq_id( 58876 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-01-28 13:26:39 +0000 (Tue, 28 Jan 2020)" );
	script_tag( name: "creation_date", value: "2013-04-09 16:49:46 +0530 (Tue, 09 Apr 2013)" );
	script_name( "PostgreSQL Denial of Service Vulnerability - Apr13 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52837" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1028387" );
	script_xref( name: "URL", value: "http://www.postgresql.org/about/news/1456" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "postgresql_detect.sc", "secpod_postgresql_detect_lin.sc", "secpod_postgresql_detect_win.sc", "os_detection.sc" );
	script_mandatory_keys( "postgresql/detected", "Host/runs_windows" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  SQL query, gain access or manipulate arbitrary files, and cause denial of service." );
	script_tag( name: "affected", value: "PostgreSQL version 9.2.x before 9.2.4, 9.1.x before 9.1.9, and
  9.0.x before 9.0.13." );
	script_tag( name: "insight", value: "Improper validation of connection request that contains database name
  begins with the '-' symbol." );
	script_tag( name: "solution", value: "Upgrade to PostgreSQL 9.0.13, 9.1.9, 9.2.4 or later." );
	script_tag( name: "summary", value: "This host is installed with PostgreSQL and is prone to denial
  of service vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(!IsMatchRegexp( vers, "^9\\.[0-2]\\." )){
	exit( 99 );
}
if(version_in_range( version: vers, test_version: "9.0", test_version2: "9.0.12" ) || version_in_range( version: vers, test_version: "9.1", test_version2: "9.1.8" ) || version_in_range( version: vers, test_version: "9.2", test_version2: "9.2.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

