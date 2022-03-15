CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141885" );
	script_version( "2021-08-27T13:01:16+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 13:01:16 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-01-17 15:08:01 +0700 (Thu, 17 Jan 2019)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-18 16:14:00 +0000 (Fri, 18 Jan 2019)" );
	script_cve_id( "CVE-2018-20719" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Tiki Wiki CMS Groupware < 17.2 SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_tikiwiki_detect.sc" );
	script_mandatory_keys( "TikiWiki/installed" );
	script_tag( name: "summary", value: "In Tiki the user task component is vulnerable to a SQL Injection via the
tiki-user_tasks.php show_history parameter." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Tiki Wiki CMS Groupware prior to version 17.2." );
	script_tag( name: "solution", value: "Upgrade to version 17.2 or later." );
	script_xref( name: "URL", value: "https://blog.ripstech.com/2018/scan-verify-patch-security-issues-in-minutes/" );
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
if(version_is_less( version: version, test_version: "17.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "17.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

