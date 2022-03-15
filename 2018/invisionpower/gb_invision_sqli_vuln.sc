CPE = "cpe:/a:invision_power_services:invision_power_board";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113143" );
	script_version( "2021-07-01T11:00:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-01 11:00:40 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "creation_date", value: "2018-03-22 12:47:45 +0100 (Thu, 22 Mar 2018)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-03 14:55:00 +0000 (Wed, 03 Jun 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2014-4928" );
	script_name( "Invision Power Board 3.4.5 SQLi Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "invision_power_board_detect.sc" );
	script_mandatory_keys( "invision_power_board/installed" );
	script_tag( name: "summary", value: "Invision Power Board is prone to an SQL Injection Vulnerability." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to insufficient sanitation of the 'cld' parameter." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to execute arbitrary SQL
commands on the target system. This would result in effects ranging from information disclosure to gaining
complete access over the target system." );
	script_tag( name: "affected", value: "Invision Power Board through version 3.4.5." );
	script_tag( name: "solution", value: "Update to version 3.4.6." );
	script_xref( name: "URL", value: "http://dringen.blogspot.de/2014/07/invision-power-board-blind-sql.html" );
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
if(version_is_less( version: version, test_version: "3.4.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.4.6" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

