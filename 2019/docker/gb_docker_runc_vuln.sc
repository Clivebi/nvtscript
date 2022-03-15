CPE = "cpe:/a:docker:docker";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141997" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-02-14 11:54:46 +0700 (Thu, 14 Feb 2019)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-01 20:15:00 +0000 (Thu, 01 Jul 2021)" );
	script_cve_id( "CVE-2019-5736" );
	script_bugtraq_id( 106976 );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Docker < 18.09.2 runc Command Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_docker_http_rest_api_detect.sc", "gb_docker_ssh_login_detect.sc" );
	script_mandatory_keys( "docker/version" );
	script_tag( name: "summary", value: "Docker is prone to a command execution vulnerability." );
	script_tag( name: "insight", value: "runc through 1.0-rc6, as used in Docker, allows attackers to
  overwrite the host runc binary (and consequently obtain host root access) by leveraging the
  ability to execute a command as root within one of these types of containers: (1) a new container
  with an attacker-controlled image, or (2) an existing container, to which the attacker previously
  had write access, that can be attached with docker exec. This occurs because of file-descriptor
  mishandling, related to /proc/self/exe." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Docker prior to version 18.09.2." );
	script_tag( name: "solution", value: "Update to version 18.09.2 or later." );
	script_xref( name: "URL", value: "https://docs.docker.com/engine/release-notes/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "18.09.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "18.09.2" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

