CPE = "cpe:/a:manageengine:password_manager_pro";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812501" );
	script_version( "2021-09-13T08:01:46+0000" );
	script_cve_id( "CVE-2017-17698" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-13 08:01:46 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-29 15:17:00 +0000 (Fri, 29 Dec 2017)" );
	script_tag( name: "creation_date", value: "2017-12-19 10:23:27 +0530 (Tue, 19 Dec 2017)" );
	script_name( "ManageEngine Password Manager Pro Multiple XSS Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with ManageEngine
  Password Manager Pro and is prone to multiple cross site scripting
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to an improper
  sanitization of input in 'SearchResult.ec' and 'BulkAccessControlView.ec'." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "ManageEngine Password Manager Pro
  version 9.0 before 9.4 (9400)" );
	script_tag( name: "solution", value: "Upgrade to ManageEngine Password Manager Pro
  version 9.4(9400) or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://www.manageengine.com/products/passwordmanagerpro/release-notes.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_manage_engine_pass_mang_pro_detect.sc" );
	script_mandatory_keys( "ManageEngine/Password_Manager/installed" );
	script_require_ports( "Services/www", 7272 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!mePort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: mePort, exit_no_version: TRUE )){
	exit( 0 );
}
meVer = infos["version"];
path = infos["location"];
if(( version_in_range( version: meVer, test_version: "9000", test_version2: "9300" ) )){
	report = report_fixed_ver( installed_version: meVer, fixed_version: "9.4(9400)", install_path: path );
	security_message( data: report, port: mePort );
	exit( 0 );
}

