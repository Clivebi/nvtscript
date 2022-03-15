CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146737" );
	script_version( "2021-09-22T07:15:16+0000" );
	script_tag( name: "last_modification", value: "2021-09-22 07:15:16 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-21 09:40:25 +0000 (Tue, 21 Sep 2021)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2015-7698" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ownCloud <= 8.1.1 RCE Vulnerability (oC-SA-2015-017)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc" );
	script_mandatory_keys( "owncloud/installed" );
	script_tag( name: "summary", value: "ownCloud is prone to a remote code execution (RCE)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "icewind1991 SMB, as used in ownCloud, allows remote
  authenticated users to execute arbitrary SMB commands via shell metacharacters in the user
  argument in the listShares function in Server.php or the connect or read function in Share.php." );
	script_tag( name: "affected", value: "ownCloud version 8.1.1 and prior." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://github.com/owncloud/security-advisories/blob/master/server/oc-sa-2015-017.json" );
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
if(version_is_less_equal( version: version, test_version: "8.1.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

