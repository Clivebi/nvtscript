if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112349" );
	script_version( "2020-12-09T13:05:49+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-12-09 13:05:49 +0000 (Wed, 09 Dec 2020)" );
	script_tag( name: "creation_date", value: "2018-08-06 13:03:00 +0200 (Mon, 06 Aug 2018)" );
	script_name( "Sensiolabs Symfony End of Life (EOL) Detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_symfony_consolidation.sc" );
	script_mandatory_keys( "symfony/detected" );
	script_xref( name: "URL", value: "https://symfony.com/roadmap" );
	script_tag( name: "summary", value: "Sensiolabs Symfony on the remote host has reached the End of Life (EOL) and should
  not be used anymore." );
	script_tag( name: "impact", value: "An EOL version of Sensiolabs Symfony is not receiving any security updates from the vendor.
  Unfixed security vulnerabilities might be leveraged by an attacker to compromise the security of this host." );
	script_tag( name: "solution", value: "Update Symfony to the latest available and supported version." );
	script_tag( name: "vuldetect", value: "Checks if an EOL version is present on the target host." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
CPE = "cpe:/a:sensiolabs:symfony";
require("host_details.inc.sc");
require("products_eol.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(ret = product_reached_eol( cpe: CPE, version: version )){
	if(port){
		location = http_report_vuln_url( port: port, url: location, url_only: TRUE );
	}
	report = build_eol_message( name: "Sensiolabs Symfony", cpe: CPE, version: version, location: location, eol_version: ret["eol_version"], eol_date: ret["eol_date"], eol_type: "prod" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

