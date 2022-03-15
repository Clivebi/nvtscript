if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113026" );
	script_version( "2021-03-26T13:22:13+0000" );
	script_tag( name: "last_modification", value: "2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-10-16 12:39:40 +0200 (Mon, 16 Oct 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ISC BIND End of Life (EOL) Detection - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_isc_bind_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "isc/bind/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "The ISC BIND version on the remote host has reached
  the End of Life (EOL) and should not be used anymore." );
	script_tag( name: "impact", value: "An EOL version of ISC BIND is not receiving
  any security updates from the vendor. Unfixed security vulnerabilities might be
  leveraged by an attacker to compromise the security of this host." );
	script_tag( name: "solution", value: "Update the ISC BIND version on the remote host to
  a still supported version." );
	script_tag( name: "vuldetect", value: "Checks if an EOL version is present on the target host." );
	script_xref( name: "URL", value: "https://www.isc.org/downloads/software-support-policy/" );
	script_xref( name: "URL", value: "https://www.isc.org/downloads/" );
	exit( 0 );
}
CPE = "cpe:/a:isc:bind";
require("misc_func.inc.sc");
require("products_eol.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_full( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
proto = infos["proto"];
location = infos["location"];
if(ret = product_reached_eol( cpe: CPE, version: version )){
	report = build_eol_message( name: "ISC BIND", cpe: CPE, version: version, location: location, eol_version: ret["eol_version"], eol_date: ret["eol_date"], eol_type: "prod" );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );

