CPE = "cpe:/a:jquery:jquery";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117148" );
	script_version( "2021-06-11T09:02:34+0000" );
	script_tag( name: "last_modification", value: "2021-06-11 09:02:34 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-01-12 09:05:04 +0000 (Tue, 12 Jan 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-01-12 09:05:04 +0000 (Tue, 12 Jan 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "jQuery End of Life (EOL) Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jquery_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "jquery/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "The installed version of jQuery on the remote host has reached
  the End of Life (EOL) and should not be used anymore." );
	script_tag( name: "impact", value: "An EOL version of jQuery is not receiving any security updates
  from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise
  the security of this host." );
	script_tag( name: "solution", value: "Update jQuery on the remote host to a still supported version." );
	script_tag( name: "vuldetect", value: "Checks if an EOL version is present on the target host." );
	script_xref( name: "URL", value: "https://github.com/jquery/jquery.com/pull/163" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("products_eol.inc.sc");
require("list_array_func.inc.sc");
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
	report = build_eol_message( name: "jQuery", cpe: CPE, version: version, location: http_report_vuln_url( port: port, url: location, url_only: TRUE ), eol_version: ret["eol_version"], eol_date: ret["eol_date"], eol_type: "prod" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

