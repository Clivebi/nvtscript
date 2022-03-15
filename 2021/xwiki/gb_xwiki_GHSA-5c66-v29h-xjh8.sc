CPE = "cpe:/a:xwiki:xwiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145816" );
	script_version( "2021-08-27T08:01:04+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 08:01:04 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-04-23 02:26:34 +0000 (Fri, 23 Apr 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-22 19:43:00 +0000 (Fri, 22 Jan 2021)" );
	script_cve_id( "CVE-2021-3137" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "XWiki XSS Vulnerability (GHSA-5c66-v29h-xjh8)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_xwiki_enterprise_detect.sc" );
	script_mandatory_keys( "xwiki/detected" );
	script_tag( name: "summary", value: "XWiki is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It is possible to persistently inject scripts in XWiki. Unregistered
  users can fill simple text fields. Registered users can fill in their personal information and (if
  they have edit  rights) fill the values of static lists using App Within Minutes." );
	script_tag( name: "impact", value: "Successful exploitation can lead to user's session hijacking, and
  if used in conjunction with a social engineering attack it can also lead to disclosure of sensitive
  data, CSRF attacks and other security vulnerabilities. That can also lead to the attacker taking over
  an account. If the victim has administrative rights it might even lead to code execution on the server,
  depending on the application and the privileges of the account." );
	script_tag( name: "affected", value: "XWiki through versions prior to 12.6.3 or 12.8." );
	script_tag( name: "solution", value: "Update to version 12.6.3, 12.8 or later." );
	script_xref( name: "URL", value: "https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-5c66-v29h-xjh8" );
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
if(version_is_less( version: version, test_version: "12.6.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "12.6.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^12\\.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "12.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

