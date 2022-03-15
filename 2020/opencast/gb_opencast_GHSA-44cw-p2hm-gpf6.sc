CPE = "cpe:/a:opencast:opencast";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145019" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-12-10 07:35:23 +0000 (Thu, 10 Dec 2020)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-10 20:57:00 +0000 (Thu, 10 Dec 2020)" );
	script_cve_id( "CVE-2020-26234" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenCast < 7.9, 8.0 < 8.9 Hostname Verification Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_opencast_detect.sc" );
	script_mandatory_keys( "opencast/detected" );
	script_tag( name: "summary", value: "OpenCast is prone to a hostname verification vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Opencast disables HTTPS hostname verification of its HTTP client used for a
  large portion of Opencast's HTTP requests.

  Hostname verification is an important part when using HTTPS to ensure that the presented certificate is valid
  for the host. Disabling it can allow for man-in-the-middle attacks." );
	script_tag( name: "affected", value: "OpenCast versions prior to 7.9 and versions 8.0 - 8.8." );
	script_tag( name: "solution", value: "Update to version 7.9, 8.9 or later." );
	script_xref( name: "URL", value: "https://github.com/opencast/opencast/security/advisories/GHSA-44cw-p2hm-gpf6" );
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
if(version_is_less( version: version, test_version: "7.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.9", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.9", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

