if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112591" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-06-03 15:17:00 +0200 (Mon, 03 Jun 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-03 21:15:00 +0000 (Sat, 03 Aug 2019)" );
	script_cve_id( "CVE-2019-10866" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Form Maker Plugin < 1.13.3 SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/form-maker/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Form Maker is prone to an SQL injection vulnerability." );
	script_tag( name: "insight", value: "In the Form Maker plugin for WordPress,
  it is possible to achieve SQL injection in the function get_labels_parameters in the file
  form-maker/admin/models/Submissions_fm.php with a crafted value of the /models/Submissioc parameter." );
	script_tag( name: "affected", value: "WordPress Form Maker plugin before version 1.13.3." );
	script_tag( name: "solution", value: "Update to version 1.13.3 or later." );
	script_xref( name: "URL", value: "https://seclists.org/fulldisclosure/2019/May/8" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/form-maker/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:10web:form-maker";
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
if(version_is_less( version: version, test_version: "1.13.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.13.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

