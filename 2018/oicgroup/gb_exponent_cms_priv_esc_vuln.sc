if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113140" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-20 13:55:55 +0100 (Tue, 20 Mar 2018)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-18213" );
	script_name( "Exponent CMS 2.4.1 Patch 5 - Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_exponet_cms_detect.sc" );
	script_mandatory_keys( "ExponentCMS/installed" );
	script_tag( name: "summary", value: "Exponent CMS allows rogue admins to elevate their privileges." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Exponent CMS version 2.0.0 through 2.4.1 Patch 5." );
	script_tag( name: "solution", value: "Update to 2.4.1 Patch 6." );
	script_xref( name: "URL", value: "http://www.exponentcms.org/news/patch-6-released-for-v2-4-1-to-fix-a-few-big-issues" );
	script_xref( name: "URL", value: "https://github.com/exponentcms/exponent-cms/releases/tag/v2.4.1patch6" );
	exit( 0 );
}
CPE = "cpe:/a:exponentcms:exponent_cms";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.4.1.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.4.1.6" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

