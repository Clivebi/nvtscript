CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144858" );
	script_version( "2021-08-11T08:56:08+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-10-29 04:26:05 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-25 20:10:00 +0000 (Thu, 25 Feb 2021)" );
	script_cve_id( "CVE-2020-36251" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ownCloud < 10.3.0 Group Share Deletion Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc" );
	script_mandatory_keys( "owncloud/installed" );
	script_tag( name: "summary", value: "ownCloud is prone to a vulnerability where it is possible to delete a
  received group share for whole group." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A group-share recipient can remove the received group share for all
  group-recipients. No data-loss occurs as the share can be re-created again." );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker, who has received non-administrative access
  to a group share, to remove everyone else's access to that share." );
	script_tag( name: "affected", value: "ownCloud versions prior to 10.3.0." );
	script_tag( name: "solution", value: "Update to version 10.3.0 or later." );
	script_xref( name: "URL", value: "https://owncloud.com/security-advisories/deleting-received-group-share-for-whole-group/" );
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
if(version_is_less( version: version, test_version: "10.3.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.3.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

