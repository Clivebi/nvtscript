CPE = "cpe:/a:quest:kace_systems_management_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140288" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-09 12:28:27 +0700 (Wed, 09 Aug 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-15 16:34:00 +0000 (Tue, 15 Aug 2017)" );
	script_cve_id( "CVE-2017-12567" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dell KACE Systems Management Appliance SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_quest_kace_sma_detect.sc" );
	script_mandatory_keys( "quest_kace_sma/detected", "quest_kace_sma/model" );
	script_tag( name: "summary", value: "An SQL injection exists in Dell/Quest KACE Asset Management Appliance." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "KACE Asset Management Appliance version 6.4.120822 until 7.2.101." );
	script_tag( name: "solution", value: "Update to the latest version." );
	script_xref( name: "URL", value: "https://support.quest.com/kace-systems-management-appliance/kb/231874" );
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
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.4.120822", test_version2: "7.2.101" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

