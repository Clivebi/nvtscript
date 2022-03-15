CPE = "cpe:/a:docker:docker";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142670" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-07-29 04:04:50 +0000 (Mon, 29 Jul 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-27 17:15:00 +0000 (Tue, 27 Aug 2019)" );
	script_cve_id( "CVE-2019-13509" );
	script_bugtraq_id( 109253 );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Docker < 18.09.8 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_docker_http_rest_api_detect.sc", "gb_docker_ssh_login_detect.sc" );
	script_mandatory_keys( "docker/version" );
	script_tag( name: "summary", value: "Docker is prone to an information disclosure vulnerability." );
	script_tag( name: "insight", value: "Docker Engine in debug mode may sometimes add secrets to the
  debug log. This applies to a scenario where docker stack deploy is run to redeploy a stack that
  includes (non external) secrets. It potentially applies to other API users of the stack API if
  they resend the secret." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Docker prior to version 18.09.8." );
	script_tag( name: "solution", value: "Update to version 18.09.8 or later." );
	script_xref( name: "URL", value: "https://docs.docker.com/engine/release-notes/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "18.09.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "18.09.8" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

