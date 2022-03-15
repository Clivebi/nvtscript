CPE = "cpe:/a:xwiki:xwiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145169" );
	script_version( "2021-08-27T08:01:04+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 08:01:04 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-15 07:35:50 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-05 21:15:00 +0000 (Tue, 05 Jan 2021)" );
	script_cve_id( "CVE-2020-13654" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "XWiki < 12.8 Escaping Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_xwiki_enterprise_detect.sc" );
	script_mandatory_keys( "xwiki/detected" );
	script_tag( name: "summary", value: "XWiki Platform mishandles escaping in the property displayer." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "XWiki prior to version 12.8." );
	script_tag( name: "solution", value: "Update to version 12.8 or later." );
	script_xref( name: "URL", value: "https://github.com/xwiki/xwiki-platform/pull/1315" );
	script_xref( name: "URL", value: "https://jira.xwiki.org/browse/XWIKI-17374" );
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
if(version_is_less( version: version, test_version: "12.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "12.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

