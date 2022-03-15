if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112497" );
	script_version( "2021-08-30T14:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 14:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-07-01 11:30:11 +0200 (Mon, 01 Jul 2019)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-04 18:15:00 +0000 (Sun, 04 Oct 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-19039" );
	script_bugtraq_id( 105994 );
	script_name( "Grafana 4.1.0 through 5.3.2 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_grafana_http_detect.sc" );
	script_mandatory_keys( "grafana/detected" );
	script_tag( name: "summary", value: "Grafana is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability allows any users with Editor or Admin permissions
  in Grafana to read any file that the Grafana process can read from the filesystem." );
	script_tag( name: "impact", value: "Successful exploitation of these vulnerabilities could lead to disclosure
  of sensitive information or addition or modification of data." );
	script_tag( name: "affected", value: "Grafana 4.1.0 through 5.3.2." );
	script_tag( name: "solution", value: "Update to version 4.6.5 or 5.3.3 respectively." );
	script_xref( name: "URL", value: "https://community.grafana.com/t/grafana-5-3-3-and-4-6-5-security-update/11961" );
	exit( 0 );
}
CPE = "cpe:/a:grafana:grafana";
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
if(version_in_range( version: version, test_version: "4.1.0", test_version2: "4.6.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.6.5", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.3.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.3.3", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

