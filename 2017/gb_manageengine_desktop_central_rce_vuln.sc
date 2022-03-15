CPE = "cpe:/a:zohocorp:manageengine_desktop_central";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106969" );
	script_version( "2021-09-23T03:58:52+0000" );
	script_tag( name: "last_modification", value: "2021-09-23 03:58:52 +0000 (Thu, 23 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-19 15:54:44 +0700 (Wed, 19 Jul 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-12 01:29:00 +0000 (Sat, 12 Aug 2017)" );
	script_cve_id( "CVE-2017-11346" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ManageEngine Desktop Central < 10.0.092 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_manage_engine_desktop_central_http_detect.sc" );
	script_mandatory_keys( "manageengine/desktop_central/detected" );
	script_tag( name: "summary", value: "ManageEngine Desktop Central allows remote attackers to execute
  arbitrary code via vectors involving the upload of help desk videos." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "ManageEngine Desktop Central before version 10.0.092." );
	script_tag( name: "solution", value: "Update to version 10.0.092 or later." );
	script_xref( name: "URL", value: "https://www.manageengine.com/products/desktop-central/remote-code-execution.html" );
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
if(version_is_less( version: version, test_version: "10.0.092" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.0.092", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

