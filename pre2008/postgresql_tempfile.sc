CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15417" );
	script_version( "2020-06-03T08:38:58+0000" );
	script_tag( name: "last_modification", value: "2020-06-03 08:38:58 +0000 (Wed, 03 Jun 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-0977" );
	script_bugtraq_id( 11295 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "PostgreSQL insecure temporary file creation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "postgresql_detect.sc", "secpod_postgresql_detect_lin.sc", "secpod_postgresql_detect_win.sc" );
	script_mandatory_keys( "postgresql/detected" );
	script_tag( name: "solution", value: "Upgrade to newer version of this software." );
	script_tag( name: "summary", value: "The remote PostgreSQL server, according to its version number, is vulnerable
  to an unspecified insecure temporary file creation flaw." );
	script_tag( name: "impact", value: "This flaw may allow a local attacker to overwrite arbitrary files with the
  privileges of the application." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
loc = infos["location"];
if(ereg( string: vers, pattern: "^([0-6]\\.|7\\.(4\\.[0-5])|([0-3]\\..*))" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

