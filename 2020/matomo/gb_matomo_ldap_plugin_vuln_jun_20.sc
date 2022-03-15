CPE = "cpe:/a:matomo:matomo";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108804" );
	script_version( "2020-12-24T15:50:52+0000" );
	script_tag( name: "last_modification", value: "2020-12-24 15:50:52 +0000 (Thu, 24 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-06-08 08:56:32 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Matomo Analytics < 3.13.6 LDAP Plugin Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_matomo_detect.sc" );
	script_mandatory_keys( "matomo/installed" );
	script_xref( name: "URL", value: "https://matomo.org/changelog/matomo-3-13-6/" );
	script_tag( name: "summary", value: "Matomo Analytics before version 3.13.6 is prone to an unspecified
  vulnerability in the LDAP plugin." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Matomo Analytics before version 3.13.6." );
	script_tag( name: "solution", value: "Update to version 3.13.6 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!info = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = info["version"];
path = info["location"];
if(version_is_less( version: vers, test_version: "3.13.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.13.6", install_url: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

