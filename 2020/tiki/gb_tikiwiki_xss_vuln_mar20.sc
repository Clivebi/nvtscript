CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112721" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-04-02 08:32:05 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-03 16:43:00 +0000 (Fri, 03 Apr 2020)" );
	script_cve_id( "CVE-2020-8966" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Tiki Wiki CMS Groupware < 21.0 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_tikiwiki_detect.sc" );
	script_mandatory_keys( "TikiWiki/installed" );
	script_tag( name: "summary", value: "Tiki Wiki is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Some php pages receive input from an upstream component, but do not
  neutralize or incorrectly neutralize special characters such as '<', '>', and '&'. These characters
  could be interpreted as web-scripting elements when they are sent to a downstream component that processes web pages." );
	script_tag( name: "affected", value: "Tiki Wiki CMS Groupware version 20.0 and prior." );
	script_tag( name: "solution", value: "Update to version 21.0." );
	script_xref( name: "URL", value: "https://www.incibe-cert.es/en/early-warning/security-advisories/cross-site-scripting-xss-flaws-found-tiki-wiki-cms-software" );
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
if(version_is_less( version: version, test_version: "21.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "21.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

