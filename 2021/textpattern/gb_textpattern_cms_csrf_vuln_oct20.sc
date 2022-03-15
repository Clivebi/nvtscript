CPE = "cpe:/a:discourse:discourse";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146399" );
	script_version( "2021-08-27T11:01:07+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 11:01:07 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-29 07:54:30 +0000 (Thu, 29 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-02 17:03:00 +0000 (Wed, 02 Dec 2020)" );
	script_cve_id( "CVE-2020-29458" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_name( "Textpattern CMS <= 4.6.2 CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_textpattern_cms_http_detect.sc" );
	script_mandatory_keys( "textpattern_cms/detected" );
	script_tag( name: "summary", value: "Textpattern CMS is prone to a cross-site request forgery
  (CSRF) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Textpattern CMS allows CSRF via the prefs subsystem." );
	script_tag( name: "affected", value: "Textpattern CMS version 4.6.2 and probably prior." );
	script_tag( name: "solution", value: "No known solution is available as of 29th July, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/48907" );
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
if(version_is_less_equal( version: version, test_version: "4.6.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

