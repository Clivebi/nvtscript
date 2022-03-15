CPE = "cpe:/a:discourse:discourse";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117495" );
	script_version( "2021-07-16T05:28:49+0000" );
	script_tag( name: "last_modification", value: "2021-07-16 05:28:49 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-06-14 13:26:42 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Discourse 2.8.0.beta2 Security Update" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_discourse_detect.sc" );
	script_mandatory_keys( "discourse/detected" );
	script_tag( name: "summary", value: "A new Discourse update includes two security fixes." );
	script_tag( name: "insight", value: "The following flaws exist / The following security
  fixes are included:

  - XSS in bookmarks list

  - Do not allow unauthorized access to category edit UI" );
	script_tag( name: "affected", value: "Discourse version 2.8.0.beta1." );
	script_tag( name: "solution", value: "Update to version 2.8.0.beta2 or later." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://meta.discourse.org/t/2-8-0-beta2-user-directory-custom-fields-tagging-enabled-by-default-user-selectable-badge-display-and-more/193148" );
	script_xref( name: "URL", value: "https://github.com/discourse/discourse/pull/13311/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
vers = infos["version"];
if(version_is_equal( version: vers, test_version: "2.8.0.beta1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.8.0.beta2", install_path: infos["location"] );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
