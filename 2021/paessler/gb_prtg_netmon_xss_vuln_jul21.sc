CPE = "cpe:/a:paessler:prtg_network_monitor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146231" );
	script_version( "2021-09-24T08:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-09-24 08:01:25 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-07-07 02:23:01 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-22 18:40:00 +0000 (Wed, 22 Sep 2021)" );
	script_cve_id( "CVE-2021-29643" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PRTG Network Monitor < 21.3.69.1333 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_prtg_network_monitor_detect.sc" );
	script_mandatory_keys( "prtg_network_monitor/installed" );
	script_tag( name: "summary", value: "PRTG Network Monitor is prone to a cross-site scripting (XSS)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "PRTG doesn't validate all fields that are imported from Active
  Directory when creating a new user account which lead to a potential XSS vulnerability." );
	script_tag( name: "affected", value: "PRTG Network Monitor prior to version 21.3.69.1333." );
	script_tag( name: "solution", value: "Update to version 21.3.69.1333 or later." );
	script_xref( name: "URL", value: "https://www.paessler.com/prtg/history/stable#21.3.69.1333" );
	script_xref( name: "URL", value: "https://raxis.com/blog/prtg-network-monitor-cve-2021-29643" );
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
if(version_is_less( version: version, test_version: "21.3.69.1333" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "21.3.69.1333", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

