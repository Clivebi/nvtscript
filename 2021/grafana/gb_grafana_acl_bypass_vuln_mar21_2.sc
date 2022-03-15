CPE = "cpe:/a:grafana:grafana";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145676" );
	script_version( "2021-08-17T14:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 14:01:00 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-29 09:21:42 +0000 (Mon, 29 Mar 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-30 08:15:00 +0000 (Fri, 30 Apr 2021)" );
	script_cve_id( "CVE-2021-28147" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Grafana 6.1.0-beta1 - 7.4.3 Access Control Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_grafana_http_detect.sc" );
	script_mandatory_keys( "grafana/detected" );
	script_tag( name: "summary", value: "Grafana is prone to an access control bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The team sync HTTP API in Grafana Enterprise has an incorrect access
  control issue. On Grafana instances using an external authentication service and having the EditorsCanAdmin
  feature enabled, this vulnerability allows any authenticated user to add external groups to any existing
  team. This can be used to grant a user team permissions that the user isn't supposed to have." );
	script_tag( name: "affected", value: "Grafana version 6.1.0-beta1 through 7.4.4." );
	script_tag( name: "solution", value: "Update to version 6.7.6, 7.3.10, 7.4.5 or later." );
	script_xref( name: "URL", value: "https://community.grafana.com/t/grafana-enterprise-6-7-6-7-3-10-and-7-4-5-security-update/44724" );
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
if(version_in_range( version: version, test_version: "6.1.0", test_version2: "6.7.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.7.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.0.0", test_version2: "7.3.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.3.10", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.4.0", test_version2: "7.4.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.4.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

