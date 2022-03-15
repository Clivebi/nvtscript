CPE = "cpe:/a:docker:docker";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145328" );
	script_version( "2021-09-08T13:19:15+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 13:19:15 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-02-08 03:06:25 +0000 (Mon, 08 Feb 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-10 05:15:00 +0000 (Sat, 10 Jul 2021)" );
	script_cve_id( "CVE-2021-21284", "CVE-2021-21285" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Docker < 19.03.15, 20.x < 20.10.3 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_docker_http_rest_api_detect.sc", "gb_docker_ssh_login_detect.sc" );
	script_mandatory_keys( "docker/version" );
	script_tag( name: "summary", value: "Docker is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-21284: Access to remapped root allows privilege escalation to real root

  - CVE-2021-21285: Docker daemon crash during image pull of malicious image" );
	script_tag( name: "affected", value: "Docker prior to versions 19.03.15 or 20.10.3." );
	script_tag( name: "solution", value: "Update to version 19.03.15, 20.10.3 or later." );
	script_xref( name: "URL", value: "https://github.com/moby/moby/security/advisories/GHSA-7452-xqpj-6rpc" );
	script_xref( name: "URL", value: "https://github.com/moby/moby/security/advisories/GHSA-6fj5-m822-rqx8" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "19.03.15" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "19.03.15" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "20.10", test_version2: "20.10.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "20.10.3" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

