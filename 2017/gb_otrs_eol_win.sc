if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113035" );
	script_version( "2020-12-09T13:05:49+0000" );
	script_tag( name: "last_modification", value: "2020-12-09 13:05:49 +0000 (Wed, 09 Dec 2020)" );
	script_tag( name: "creation_date", value: "2017-10-16 15:04:05 +0200 (Mon, 16 Oct 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OTRS End of Life (EOL) Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "OTRS/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "The OTRS version on the remote host has reached the End of Life (EOL) and should not be used anymore." );
	script_tag( name: "impact", value: "An EOL version of OTRS is not receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host." );
	script_tag( name: "solution", value: "Update the OTRS version on the remote host to a still supported version." );
	script_tag( name: "vuldetect", value: "Checks if an EOL version is present on the target host." );
	script_xref( name: "URL", value: "https://en.wikipedia.org/wiki/OTRS" );
	exit( 0 );
}
CPE = "cpe:/a:otrs:otrs";
require("misc_func.inc.sc");
require("products_eol.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(ret = product_reached_eol( cpe: CPE, version: version )){
	report = build_eol_message( name: "OTRS", cpe: CPE, version: version, location: http_report_vuln_url( port: port, url: location, url_only: TRUE ), eol_version: ret["eol_version"], eol_date: ret["eol_date"], eol_type: "prod" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

