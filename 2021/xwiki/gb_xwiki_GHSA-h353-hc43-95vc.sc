CPE = "cpe:/a:xwiki:xwiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146058" );
	script_version( "2021-08-27T08:01:04+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 08:01:04 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-02 05:40:29 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-25 14:15:00 +0000 (Fri, 25 Jun 2021)" );
	script_cve_id( "CVE-2021-32621" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "XWiki Script Injection Vulnerability (GHSA-h353-hc43-95vc)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_xwiki_enterprise_detect.sc" );
	script_mandatory_keys( "xwiki/detected" );
	script_tag( name: "summary", value: "XWiki is prone to a script injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A user without Script or Programming rights is able to execute
  scripts requiring privileges by editing gadget titles in the dashboard." );
	script_tag( name: "affected", value: "XWiki version 3.0M3 through 12.6.6 and 12.7 through
  12.10.2." );
	script_tag( name: "solution", value: "Update to version 12.6.7, 12.10.3 or later." );
	script_xref( name: "URL", value: "https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-h353-hc43-95vc" );
	script_xref( name: "URL", value: "https://jira.xwiki.org/browse/XWIKI-17794" );
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
if(version_in_range( version: version, test_version: "3.0", test_version2: "12.6.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "12.6.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "12.7", test_version2: "12.10.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "12.10.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

