CPE = "cpe:/a:docker:docker";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144073" );
	script_version( "2021-07-07T11:00:41+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 11:00:41 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-06-05 08:26:19 +0000 (Fri, 05 Jun 2020)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-27 00:15:00 +0000 (Thu, 27 Aug 2020)" );
	script_cve_id( "CVE-2020-13401" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Docker < 19.03.11 IPv6 Spoofing Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_docker_http_rest_api_detect.sc", "gb_docker_ssh_login_detect.sc" );
	script_mandatory_keys( "docker/version" );
	script_tag( name: "summary", value: "Docker is prone to an IPv6 spoofing vulnerability." );
	script_tag( name: "insight", value: "An issue was discovered in Docker Engine. An attacker in a
  container, with the CAP_NET_RAW capability, can craft IPv6 router advertisements, and consequently
  spoof external IPv6 hosts, obtain sensitive information, or cause a denial of service." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Docker prior to version 19.03.11." );
	script_tag( name: "solution", value: "Update to version 19.03.11 or later." );
	script_xref( name: "URL", value: "https://github.com/docker/docker-ce/releases/tag/v19.03.11" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "19.03.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "19.03.11" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

