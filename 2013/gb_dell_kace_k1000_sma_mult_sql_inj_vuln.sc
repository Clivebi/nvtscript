CPE = "cpe:/a:quest:kace_systems_management_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803735" );
	script_version( "2020-03-11T14:32:35+0000" );
	script_cve_id( "CVE-2014-1671" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-03-11 14:32:35 +0000 (Wed, 11 Mar 2020)" );
	script_tag( name: "creation_date", value: "2013-08-12 20:18:38 +0530 (Mon, 12 Aug 2013)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dell KACE K1000 SMA Multiple SQL Injection Vulnerabilities" );
	script_tag( name: "summary", value: "This host is running Dell KACE K1000 Systems Management Appliance and is
  prone to multiple SQL injection vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to latest version of Dell KACE K1000 SMA." );
	script_tag( name: "insight", value: "Multiple flaws are due to asset.php, asset_type.php, metering.php, mi.php,
  replshare.php, kbot.php, history_log.php and service.php scripts are not properly sanitizing user-supplied input." );
	script_tag( name: "affected", value: "Dell KACE K1000 Systems Management Appliance version 5.4.70402." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to inject or manipulate
  SQL queries in the back-end database, allowing for the manipulation or disclosure of arbitrary data." );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/27039" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2013/Jul/194" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_quest_kace_sma_detect.sc" );
	script_mandatory_keys( "quest_kace_sma/detected", "quest_kace_sma/model" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
model = get_kb_item( "quest_kace_sma/model" );
if(model != "K1000"){
	exit( 0 );
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "5.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

