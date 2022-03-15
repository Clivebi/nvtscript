if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.118006" );
	script_version( "2021-08-17T14:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 14:01:00 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-04-06 15:07:59 +0200 (Tue, 06 Apr 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-04 18:16:00 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_cve_id( "CVE-2021-28935" );
	script_name( "CMS Made Simple <= 2.2.15 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cms_made_simple_detect.sc" );
	script_mandatory_keys( "cmsmadesimple/installed" );
	script_tag( name: "summary", value: "CMS Made Simple is prone to a cross-site scripting
  (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "insight", value: "The vulnerability is exploitable via the
  '/admin/addbookmark.php' script through the 'Site Admin > My Preferences > Title'
  field." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated
  attacker to inject arbitrary HTML and JavaScript into the site." );
	script_tag( name: "affected", value: "CMS Made Simple through version 2.2.15." );
	script_tag( name: "solution", value: "No known solution is available as of 06th April, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "http://dev.cmsmadesimple.org/bug/view/12432" );
	exit( 0 );
}
CPE = "cpe:/a:cmsmadesimple:cms_made_simple";
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
if(version_is_less_equal( version: version, test_version: "2.2.15" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

