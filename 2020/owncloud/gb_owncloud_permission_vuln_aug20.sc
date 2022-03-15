CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144857" );
	script_version( "2020-10-29T04:57:37+0000" );
	script_tag( name: "last_modification", value: "2020-10-29 04:57:37 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-29 04:10:58 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:C/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ownCloud < 10.2.1 Share Permission Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc" );
	script_mandatory_keys( "owncloud/installed" );
	script_tag( name: "summary", value: "ownCloud is prone to a vulnerability where it is possible to extend
  internal-share permissions using the API." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "An Attacker can extend the permission of a received subfolder share using
  the ocs api. Additional risk exists because the privilege extension is also possible on public-shares." );
	script_tag( name: "affected", value: "ownCloud version 10.2.0 and prior." );
	script_tag( name: "solution", value: "Update to version 10.2.1 or later." );
	script_xref( name: "URL", value: "https://owncloud.com/security/possibility-to-extend-internal-share-permissions-using-the-api/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "10.2.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.2.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

