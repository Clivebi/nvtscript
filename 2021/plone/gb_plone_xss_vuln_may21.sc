if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113817" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-05-12 09:15:48 +0000 (Wed, 12 May 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-24 17:05:00 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_cve_id( "CVE-2021-29002" );
	script_name( "Plone <= 5.2.4 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_plone_detect.sc" );
	script_mandatory_keys( "plone/installed" );
	script_tag( name: "summary", value: "Plone is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is exploitable by an attacker with
  manager-level access when sending JavaScript code via the orm.widgets.site_title parameter in the
  site control panel." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker to
  inject arbitrary JavaScript into the site." );
	script_tag( name: "affected", value: "Plone through version 5.2.4." );
	script_tag( name: "solution", value: "No known solution is available as of 12th May, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/49668" );
	script_xref( name: "URL", value: "https://github.com/plone/Products.CMFPlone/issues/3255" );
	exit( 0 );
}
CPE = "cpe:/a:plone:plone";
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
if(version_is_less_equal( version: version, test_version: "5.2.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

