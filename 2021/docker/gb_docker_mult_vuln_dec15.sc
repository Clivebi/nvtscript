CPE = "cpe:/a:docker:docker";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112990" );
	script_version( "2021-09-08T13:19:15+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 13:19:15 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-08 08:04:11 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2014-9356", "CVE-2014-9357", "CVE-2014-9358" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Docker < 1.3.3 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_docker_http_rest_api_detect.sc", "gb_docker_ssh_login_detect.sc" );
	script_mandatory_keys( "docker/version" );
	script_tag( name: "summary", value: "Docker is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2014-9356: A path traversal vulnerability in Docker allows remote attackers to write to
  arbitrary files and bypass a container protection mechanism via a full pathname in a symlink
  in an image or build in a Dockerfile.

  - CVE-2014-9357: Docker allows remote attackers to execute arbitrary code with root privileges
  via a crafted image or build in a Dockerfile in an LZMA (.xz) archive, related to the chroot for
  archive extraction.

  - CVE-2014-9358: Docker does not properly validate image IDs, which allows remote attackers to
  conduct path traversal attacks and spoof repositories via a crafted image in a 'docker load'
  operation or  'registry communications'." );
	script_tag( name: "affected", value: "Docker through version 1.3.2." );
	script_tag( name: "solution", value: "Update to version 1.3.3 or later." );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=1172761" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.3.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.3" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

