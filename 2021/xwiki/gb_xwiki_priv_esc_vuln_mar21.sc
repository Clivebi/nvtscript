if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113800" );
	script_version( "2021-08-27T08:01:04+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 08:01:04 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-15 11:29:02 +0000 (Mon, 15 Mar 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-22 16:26:00 +0000 (Mon, 22 Mar 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2021-21379" );
	script_name( "XWiki >= 11.4-rc-1, < 11.10.1, 12.x < 12.6.3, 12.7.x Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_xwiki_enterprise_detect.sc" );
	script_mandatory_keys( "xwiki/detected" );
	script_tag( name: "summary", value: "XWiki is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Using {{wikimacrocontent}}, a user may execute scripts
  in the context of the macro creator." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker
  to gain privileges he has not been assigned." );
	script_tag( name: "affected", value: "XWiki versions 11.4-rc-1 through 11.10.0, 12.0.0 through 12.6.2 and 12.7.0 through 12.7.1." );
	script_tag( name: "solution", value: "Update to version 11.10.1, 12.6.3 or 12.8-rc-1 respectively." );
	script_xref( name: "URL", value: "https://jira.xwiki.org/browse/XWIKI-17759" );
	script_xref( name: "URL", value: "https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-v662-xpcc-9xf6" );
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
if(version_in_range( version: version, test_version: "11.4", test_version2: "11.10.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.10.1", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "12.0.0", test_version2: "12.6.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "12.6.3", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(IsMatchRegexp( version, "^12\\.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "12.8-rc-1", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

