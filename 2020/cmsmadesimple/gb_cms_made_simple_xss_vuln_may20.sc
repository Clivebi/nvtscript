CPE = "cpe:/a:cmsmadesimple:cms_made_simple";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144021" );
	script_version( "2021-07-07T11:00:41+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 11:00:41 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-06-03 03:39:07 +0000 (Wed, 03 Jun 2020)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-29 14:02:00 +0000 (Fri, 29 May 2020)" );
	script_cve_id( "CVE-2020-13660", "CVE-2020-27377" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "CMS Made Simple <= 2.2.14 Multiple XSS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cms_made_simple_detect.sc" );
	script_mandatory_keys( "cmsmadesimple/installed" );
	script_tag( name: "summary", value: "CMS Made Simple is prone to multiple cross-site scripting (XSS)
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2020-13660: XSS via a crafted File Picker profile name

  - CVE-2020-27377: XSS in the Administrator panel on the 'Setting News' module" );
	script_tag( name: "affected", value: "CMS Made Simple version 2.2.14 and prior." );
	script_tag( name: "solution", value: "Update to version 2.2.15 or later." );
	script_xref( name: "URL", value: "http://dev.cmsmadesimple.org/bug/view/12312" );
	script_xref( name: "URL", value: "http://dev.cmsmadesimple.org/bug/view/12317" );
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
if(version_is_less_equal( version: version, test_version: "2.2.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.15", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

