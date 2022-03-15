CPE = "cpe:/a:zohocorp:manageengine_applications_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107251" );
	script_version( "2021-09-14T11:01:46+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 11:01:46 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-07 15:43:15 +0700 (Tue, 07 Nov 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-07 01:29:00 +0000 (Tue, 07 Aug 2018)" );
	script_cve_id( "CVE-2017-16542", "CVE-2017-16543" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ManageEngine Applications Manager < 13500 SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_manage_engine_appli_manager_detect.sc" );
	script_mandatory_keys( "zohocorp/manageengine_applications_manager/detected" );
	script_tag( name: "summary", value: "ManageEngine Applications Manager is prone to a SQL injection
  vulnerability." );
	script_tag( name: "insight", value: "ManageEngine Applications Manager is vulnerable to SQL injection via the
  name parameter in a manageApplications.do request and via GraphicalView.do, as demonstrated by a
  crafted viewProps yCanvas field or viewid parameter." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Zoho ManageEngine Applications Manager 13 before build 13500." );
	script_tag( name: "solution", value: "Update to Zoho ManageEngine Applications Manager 13 build 13500 or later." );
	script_xref( name: "URL", value: "https://code610.blogspot.de/2017/11/sql-injection-in-manageengine.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^13" ) && version_is_less( version: version, test_version: "13500" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "13500" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

