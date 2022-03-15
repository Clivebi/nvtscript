CPE = "cpe:/a:check_mk_project:check_mk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144005" );
	script_version( "2020-12-09T14:13:00+0000" );
	script_tag( name: "last_modification", value: "2020-12-09 14:13:00 +0000 (Wed, 09 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-05-29 04:43:48 +0000 (Fri, 29 May 2020)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Check_MK End of Life (EOL) Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_check_mk_web_detect.sc", "gb_check_mk_agent_detect.sc" );
	script_mandatory_keys( "check_mk/detected" );
	script_tag( name: "summary", value: "The Check_MK version on the remote host has reached the End of Life (EOL) and
  should not be used anymore." );
	script_tag( name: "impact", value: "An EOL version of Check_MK is not receiving any security updates from
  the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise the security of
  this host." );
	script_tag( name: "solution", value: "Update the Check_MK version on the remote host to a still supported version." );
	script_tag( name: "vuldetect", value: "Checks if an EOL version is present on the target host." );
	script_xref( name: "URL", value: "https://checkmk.de/cms_cmk_versionen.html#lifecycle" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("products_eol.inc.sc");
require("list_array_func.inc.sc");
require("http_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
if(ret = product_reached_eol( cpe: CPE, version: version )){
	location = infos["location"];
	if(location != port + "/tcp"){
		location = http_report_vuln_url( port: port, url: location, url_only: TRUE );
	}
	report = build_eol_message( name: "Check_MK", cpe: CPE, version: version, location: location, eol_version: ret["eol_version"], eol_date: ret["eol_date"], eol_type: "prod" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

