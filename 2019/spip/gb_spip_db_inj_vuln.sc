CPE = "cpe:/a:spip:spip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143275" );
	script_version( "2021-09-06T14:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-12-19 08:25:10 +0000 (Thu, 19 Dec 2019)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-28 18:15:00 +0000 (Mon, 28 Sep 2020)" );
	script_cve_id( "CVE-2019-19830" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "SPIP < 3.1.12, 3.2.x < 3.2.7 DB Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_spip_detect.sc" );
	script_mandatory_keys( "spip/detected" );
	script_tag( name: "summary", value: "SPIP is prone to a database injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "_core_/plugins/medias in SPIP allows remote authenticated authors to inject
  content into the database." );
	script_tag( name: "affected", value: "SPIP prior to version 3.1.12 and version 3.2.x prior to version 3.2.7." );
	script_tag( name: "solution", value: "Update to version 3.1.12, 3.2.7 or later." );
	script_xref( name: "URL", value: "https://blog.spip.net/Mise-a-jour-CRITIQUE-de-securite-sortie-de-SPIP-3-2-7-SPIP-3-1-12.html" );
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
if(version_is_less( version: version, test_version: "3.1.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.1.12", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.2", test_version2: "3.2.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.2.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

