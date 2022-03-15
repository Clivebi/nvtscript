if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112596" );
	script_version( "2021-08-30T14:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 14:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-07-01 12:32:22 +0200 (Mon, 01 Jul 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-13068" );
	script_name( "Grafana < 6.2.5 HTML Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_grafana_http_detect.sc" );
	script_mandatory_keys( "grafana/detected" );
	script_tag( name: "summary", value: "Grafana is prone to an HTML injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "public/app/features/panel/panel_ctrl.ts allows HTML Injection
  in panel drilldown links (via the Title or url field)." );
	script_tag( name: "affected", value: "Grafana before version 6.2.5." );
	script_tag( name: "solution", value: "Update to version 6.2.5 or later." );
	script_xref( name: "URL", value: "https://github.com/grafana/grafana/issues/17718" );
	script_xref( name: "URL", value: "https://github.com/grafana/grafana/releases/tag/v6.2.5" );
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
if(version_is_less( version: version, test_version: "6.2.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.2.5", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

