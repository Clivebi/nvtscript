CPE = "cpe:/a:domainmod:domainmod";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144826" );
	script_version( "2021-08-16T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-16 12:00:57 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-10-26 07:11:08 +0000 (Mon, 26 Oct 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-30 14:50:00 +0000 (Fri, 30 Oct 2020)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-9080" );
	script_name( "DomainMOD < 4.14.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_domainmod_http_detect.sc" );
	script_mandatory_keys( "domainmod/detected" );
	script_tag( name: "summary", value: "DomainMOD is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Use of MD5 without a salt for password storage (CVE-2019-9080)

  - Various unspecified vulnerabilities" );
	script_tag( name: "affected", value: "DomainMOD prior to version 4.14.0." );
	script_tag( name: "solution", value: "Update to version 4.14.0 or later." );
	script_xref( name: "URL", value: "https://domainmod.org/changelog/" );
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
if(version_is_less( version: version, test_version: "4.14.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.14.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

