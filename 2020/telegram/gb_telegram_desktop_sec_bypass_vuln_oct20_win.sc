if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113767" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-10-08 08:46:37 +0000 (Thu, 08 Oct 2020)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-28 18:02:00 +0000 (Thu, 28 Jan 2021)" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-17448" );
	script_name( "Telegram Desktop <= 2.1.13 Protection Mechanism Bypass Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_telegram_desktop_detect_win.sc" );
	script_mandatory_keys( "Telegram/Win/Ver" );
	script_tag( name: "summary", value: "Telegram Desktop is prone to a protection mechanism bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Telegram Desktop allows a spoofed file type to
  bypass the Dangerous File Type Execution protection mechanism,
  by using the chat windows with a filename that lacks an extension." );
	script_tag( name: "impact", value: "Successful exploitation would for example allow an attacker
  to execute arbitrary code on the target machine by sending a malicious file to the victim." );
	script_tag( name: "affected", value: "Telegram Desktop through version 2.1.13." );
	script_tag( name: "solution", value: "Update to version 2.2.0 or later." );
	script_xref( name: "URL", value: "https://github.com/VijayT007/Vulnerability-Database/blob/master/Telegram-CVE-2020-17448" );
	exit( 0 );
}
CPE = "cpe:/a:telegram:tdesktop";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.2.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.0", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

