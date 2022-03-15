if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112427" );
	script_version( "2021-05-28T06:00:18+0200" );
	script_tag( name: "last_modification", value: "2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2018-11-13 14:32:22 +0100 (Tue, 13 Nov 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-12 18:33:00 +0000 (Wed, 12 Dec 2018)" );
	script_cve_id( "CVE-2018-19126" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PrestaShop 1.7.4.x < 1.7.4.4 & 1.6.1.x < 1.6.1.23 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_prestashop_detect.sc" );
	script_mandatory_keys( "prestashop/detected" );
	script_tag( name: "summary", value: "PrestaShop allows remote attackers to execute arbitrary code via a file upload." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The issue exists on the file manager integrated in the text editor component in the Back Office.
  By exploiting a combination of security vunerabilities, an authenticated user in the Back Office could upload a malicious file
  that would then allow him or her to execute arbitrary code on the server." );
	script_tag( name: "affected", value: "PrestaShop 1.7.4.x before 1.7.4.4 and 1.6.1.x before 1.6.1.23." );
	script_tag( name: "solution", value: "Update PrestaShop to version 1.7.4.4 or 1.6.1.23 respectively." );
	script_xref( name: "URL", value: "http://build.prestashop.com/news/prestashop-1-7-4-4-1-6-1-23-maintenance-releases/" );
	script_xref( name: "URL", value: "https://github.com/PrestaShop/PrestaShop/pull/11286" );
	script_xref( name: "URL", value: "https://github.com/PrestaShop/PrestaShop/pull/11285" );
	exit( 0 );
}
CPE = "cpe:/a:prestashop:prestashop";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.7.4.0", test_version2: "1.7.4.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.7.4.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.6.1.0", test_version2: "1.6.1.22" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.6.1.23" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

