if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113027" );
	script_version( "2021-03-10T05:21:16+0000" );
	script_tag( name: "last_modification", value: "2021-03-10 05:21:16 +0000 (Wed, 10 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-10-16 13:33:34 +0200 (Mon, 16 Oct 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL End of Life (EOL) Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "The OpenSSL version on the remote host has reached the end of
  life and should not be used anymore." );
	script_tag( name: "impact", value: "An EOL version of OpenSSL is not receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host." );
	script_tag( name: "solution", value: "Update the OpenSSL version on the remote host to a still supported version." );
	script_tag( name: "vuldetect", value: "Checks if an EOL version is present on the target host." );
	script_xref( name: "URL", value: "https://www.openssl.org/policies/releasestrat.html" );
	exit( 0 );
}
CPE = "cpe:/a:openssl:openssl";
require("misc_func.inc.sc");
require("products_eol.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(ret = product_reached_eol( cpe: CPE, version: vers )){
	report = build_eol_message( name: "OpenSSL", cpe: CPE, version: vers, location: path, eol_version: ret["eol_version"], eol_date: ret["eol_date"], eol_type: "prod" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

