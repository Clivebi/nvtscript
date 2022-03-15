if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113150" );
	script_version( "2020-12-09T13:05:49+0000" );
	script_tag( name: "last_modification", value: "2020-12-09 13:05:49 +0000 (Wed, 09 Dec 2020)" );
	script_tag( name: "creation_date", value: "2018-04-04 15:26:25 +0200 (Wed, 04 Apr 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Zarafa Products End of Life (EOL) Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zarafa_webaccess_detect.sc", "gb_zarafa_webapp_detect.sc" );
	script_mandatory_keys( "zarafa/installed" );
	script_tag( name: "summary", value: "Zarafa has abandoned maintaining their products on May 1st, 2017.

  Customers are advised to switch to Kopano, a 'fork' of Zarafa." );
	script_tag( name: "insight", value: "End of Life (EOL) products don't receive any security fixes anymore and are
  prone to all vulnerabilities that were and are detected after the EOL date." );
	script_tag( name: "vuldetect", value: "Checks if the target host is using a discontinued product." );
	script_tag( name: "affected", value: "All Zarafa products." );
	script_tag( name: "solution", value: "Transition to Kopano." );
	script_xref( name: "URL", value: "https://www.zarafa.com/?" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("products_eol.inc.sc");
require("list_array_func.inc.sc");
require("http_func.inc.sc");
cpe_array = make_array( "cpe:/a:zarafa:webapp", "Zarafa WebApp", "cpe:/a:zarafa:zarafa", "Zarafa WebAccess", "cpe:/a:zarafa:zarafa_collaboration_platform", "Zarafa Collaboration Platform" );
cpe_list = make_list( "cpe:/a:zarafa:webapp",
	 "cpe:/a:zarafa:zarafa",
	 "cpe:/a:zarafa:zarafa_collaboration_platform" );
if(!port_dict = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
CPE = port_dict["cpe"];
port = port_dict["port"];
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(ret = product_reached_eol( cpe: CPE, version: version )){
	report = build_eol_message( name: cpe_array[CPE], cpe: CPE, version: version, location: http_report_vuln_url( port: port, url: location, url_only: TRUE ), eol_version: ret["eol_version"], eol_date: ret["eol_date"], eol_type: "prod" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

