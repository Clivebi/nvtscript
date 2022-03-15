CPE = "cpe:/a:xwiki:xwiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146216" );
	script_version( "2021-08-27T08:01:04+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 08:01:04 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-05 03:12:45 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-09 13:58:00 +0000 (Fri, 09 Jul 2021)" );
	script_cve_id( "CVE-2021-32730" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "XWiki Missing CSRF Protection Vulnerability (GHSA-v9j2-q4q5-cxh4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_xwiki_enterprise_detect.sc" );
	script_mandatory_keys( "xwiki/detected" );
	script_tag( name: "summary", value: "XWiki is missing CSRF protection on the password change form." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "It's possible to forge an URL that, when accessed by an admin,
  will reset the password of any user in XWiki." );
	script_tag( name: "affected", value: "XWiki versions prior to 12.10.5 and versions 13.0 and 13.1." );
	script_tag( name: "solution", value: "Update to version 12.10.5, 13.2RC1 or later." );
	script_xref( name: "URL", value: "https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-v9j2-q4q5-cxh4" );
	script_xref( name: "URL", value: "https://jira.xwiki.org/browse/XWIKI-18315" );
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
if(version_is_less( version: version, test_version: "12.10.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "12.10.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^13\\.[01]" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "13.2RC1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

