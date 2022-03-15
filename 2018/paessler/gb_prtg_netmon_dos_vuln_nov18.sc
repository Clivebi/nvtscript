if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113300" );
	script_version( "2021-06-30T11:00:43+0000" );
	script_tag( name: "last_modification", value: "2021-06-30 11:00:43 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-13 15:39:34 +0200 (Tue, 13 Nov 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-19203" );
	script_name( "PRTG Network Monitor <=18.2.40.1683 Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_prtg_network_monitor_detect.sc" );
	script_mandatory_keys( "prtg_network_monitor/installed" );
	script_tag( name: "summary", value: "PRTG Network Monitor is prone to a Denial of Service (DoS) Vulnerability" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Remote authenticated attackers can terminate the PRTG Core Server
  via a specially crafted HTTP request." );
	script_tag( name: "affected", value: "PRTG Network Monitor through version 18.2.40.1683." );
	script_tag( name: "solution", value: "Update to version 18.2.41.1652." );
	script_xref( name: "URL", value: "https://www.ptsecurity.com/ww-en/analytics/threatscape/pt-2018-22/" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/lab/PT-2018-22" );
	exit( 0 );
}
CPE = "cpe:/a:paessler:prtg_network_monitor";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "18.2.41.1652" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "18.2.41.1652" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

