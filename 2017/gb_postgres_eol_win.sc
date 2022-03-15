CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108185" );
	script_version( "2020-08-25T05:50:37+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-25 05:50:37 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-02-14 13:48:20 +0100 (Tue, 14 Feb 2017)" );
	script_name( "PostgreSQL End Of Life Detection (Windows)" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "postgresql_detect.sc", "secpod_postgresql_detect_lin.sc", "secpod_postgresql_detect_win.sc", "os_detection.sc" );
	script_mandatory_keys( "postgresql/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "https://www.postgresql.org/support/versioning/" );
	script_tag( name: "summary", value: "The PostgreSQL version on the remote host has reached the end of life and should
  not be used anymore." );
	script_tag( name: "impact", value: "An end of life version of PostgreSQL is not receiving any security updates from the
  vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise the security of this host." );
	script_tag( name: "solution", value: "Update the PostgreSQL version on the remote host to a still supported version." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("products_eol.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!info = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = info["version"];
location = info["location"];
if(ret = product_reached_eol( cpe: CPE, version: version )){
	report = build_eol_message( name: "PostgreSQL", cpe: CPE, version: version, location: location, eol_version: ret["eol_version"], eol_date: ret["eol_date"], eol_type: "prod" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

