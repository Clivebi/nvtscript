if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113809" );
	script_version( "2021-08-27T08:01:04+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 08:01:04 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-26 09:58:20 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-24 15:08:00 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2021-21380" );
	script_name( "XWiki < 12.9RC1 SQLi Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_xwiki_enterprise_detect.sc" );
	script_mandatory_keys( "xwiki/detected" );
	script_tag( name: "summary", value: "XWiki is prone to an SQL injection (SQLi) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists within the Ratings API." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker
  to read and modify sensitive information or execute arbitrary code on the target system." );
	script_tag( name: "affected", value: "XWiki through version 12.8.

  Note: The vulnerability exists in the Ratings API, which is not installed by default." );
	script_tag( name: "solution", value: "Update to version 12.9RC1 or later." );
	script_xref( name: "URL", value: "https://jira.xwiki.org/browse/XWIKI-17662" );
	script_xref( name: "URL", value: "https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-79rg-7mv3-jrr5" );
	exit( 0 );
}
CPE = "cpe:/a:xwiki:xwiki";
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
if(version_is_less( version: version, test_version: "12.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "12.9RC1", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

