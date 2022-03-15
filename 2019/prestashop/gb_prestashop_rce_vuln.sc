CPE = "cpe:/a:prestashop:prestashop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141886" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-01-17 15:39:38 +0700 (Thu, 17 Jan 2019)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-04 13:41:00 +0000 (Mon, 04 Feb 2019)" );
	script_cve_id( "CVE-2018-20717" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PrestaShop < 1.7.2.5 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_prestashop_detect.sc" );
	script_mandatory_keys( "prestashop/detected" );
	script_tag( name: "summary", value: "In the orders section of PrestaShop, an attack is possible after gaining
  access to a target store with a user role with the rights of at least a Salesman or higher privileges. The
  attacker can then inject arbitrary PHP objects into the process and abuse an object chain in order to gain Remote
  Code Execution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "PrestaShop version 1.7.2.4 and prior." );
	script_tag( name: "solution", value: "Update to version 1.7.2.5 or later." );
	script_xref( name: "URL", value: "https://build.prestashop.com/news/prestashop-1-7-2-5-maintenance-release/" );
	script_xref( name: "URL", value: "https://blog.ripstech.com/2018/prestashop-remote-code-execution/" );
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
if(version_is_less( version: version, test_version: "1.7.2.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.7.2.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

