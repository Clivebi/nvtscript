CPE = "cpe:/a:docker:docker";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112992" );
	script_version( "2021-09-09T07:55:52+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 07:55:52 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-08 08:04:11 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-05 17:38:00 +0000 (Tue, 05 Jan 2021)" );
	script_cve_id( "CVE-2016-3697" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Docker < 1.11.2 Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_docker_http_rest_api_detect.sc", "gb_docker_ssh_login_detect.sc" );
	script_mandatory_keys( "docker/version" );
	script_tag( name: "summary", value: "Docker is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "libcontainer/user/user.go in runC, as used in Docker,
  improperly treats a numeric UID as a potential username, which allows local users to gain
  privileges via a numeric username in the password file in a container." );
	script_tag( name: "affected", value: "Docker through version 1.11.1." );
	script_tag( name: "solution", value: "Update to version 1.11.2 or later." );
	script_xref( name: "URL", value: "https://github.com/moby/moby/issues/21436" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.11.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.11.2" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

