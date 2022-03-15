CPE = "cpe:/a:discourse:discourse";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146786" );
	script_version( "2021-10-04T08:02:33+0000" );
	script_tag( name: "last_modification", value: "2021-10-04 08:02:33 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "creation_date", value: "2021-09-27 09:32:26 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-29 21:34:00 +0000 (Wed, 29 Sep 2021)" );
	script_cve_id( "CVE-2020-24327" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Discourse < 2.6.0 SSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_discourse_detect.sc" );
	script_mandatory_keys( "discourse/detected" );
	script_tag( name: "summary", value: "Discouse is prone to a server-side request forgery (SSRF)
  vulnerability." );
	script_tag( name: "insight", value: "An SSRF vulnerability exists via the email function. When
  writing an email in an editor, you can upload pictures of remote websites." );
	script_tag( name: "affected", value: "Discourse prior to version 2.6.0." );
	script_tag( name: "solution", value: "Update to version 2.6.0 or later." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://github.com/discourse/discourse/pull/10509" );
	script_xref( name: "URL", value: "https://meta.discourse.org/t/discourse-version-2-6/151394" );
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
if(version_is_less( version: version, test_version: "2.6.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.6.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

