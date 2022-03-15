CPE = "cpe:/a:docker:docker";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142793" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-08-27 02:13:49 +0000 (Tue, 27 Aug 2019)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-13139" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Docker < 18.09.4 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_docker_http_rest_api_detect.sc", "gb_docker_ssh_login_detect.sc" );
	script_mandatory_keys( "docker/version" );
	script_tag( name: "summary", value: "Docker is prone to a remote code execution (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An attacker who is capable of supplying or manipulating the
  build path for the 'docker build' command would be able to gain command execution. An issue exists
  in the way 'docker build' processes remote git URLs, and results in command injection into the
  underlying 'git clone' command, leading to code execution in the context of the user executing the
  'docker build' command. This occurs because git ref can be misinterpreted as a flag." );
	script_tag( name: "affected", value: "Docker prior to version 18.09.4." );
	script_tag( name: "solution", value: "Update to version 18.09.4 or later." );
	script_xref( name: "URL", value: "https://docs.docker.com/engine/release-notes/#18094" );
	script_xref( name: "URL", value: "https://github.com/moby/moby/pull/38944" );
	script_xref( name: "URL", value: "https://staaldraad.github.io/post/2019-07-16-cve-2019-13139-docker-build/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "18.09.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "18.09.4" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

