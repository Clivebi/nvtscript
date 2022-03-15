CPE = "cpe:/a:opencast:opencast";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112906" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-17 07:51:11 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-23 19:55:00 +0000 (Wed, 23 Jun 2021)" );
	script_cve_id( "CVE-2021-32623" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenCast < 9.6 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_opencast_detect.sc" );
	script_mandatory_keys( "opencast/detected" );
	script_tag( name: "summary", value: "OpenCast is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Opencast is vulnerable to a so called billion laughs attack,
  which allows an attacker to easily execute a (seemingly permanent) denial of service attack,
  essentially taking down Opencast using a single HTTP request. To exploit this, users need to
  have ingest privileges, limiting the group of potential attackers." );
	script_tag( name: "impact", value: "Successful exploitation will lead to a denial of service,
  affecting the whole application." );
	script_tag( name: "affected", value: "OpenCast prior to version 9.6." );
	script_tag( name: "solution", value: "Update to version 9.6 or later." );
	script_xref( name: "URL", value: "https://github.com/opencast/opencast/security/advisories/GHSA-9gwx-9cwp-5c2m" );
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
if(version_is_less( version: version, test_version: "9.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

