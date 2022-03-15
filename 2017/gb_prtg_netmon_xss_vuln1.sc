CPE = "cpe:/a:paessler:prtg_network_monitor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140328" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-28 13:24:55 +0700 (Mon, 28 Aug 2017)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-12 01:29:00 +0000 (Tue, 12 Sep 2017)" );
	script_cve_id( "CVE-2017-12879" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PRTG Network Monitor XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_prtg_network_monitor_detect.sc" );
	script_mandatory_keys( "prtg_network_monitor/installed" );
	script_tag( name: "summary", value: "PRTG Network Monitor is prone to a cross-site scripting vulnerability which
allows remote attackers to inject arbitrary web script or HTML via unspecified vectors." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "PRTG Network Monitor before version 17.3.33.2654." );
	script_tag( name: "solution", value: "Update to 17.3.33.2654 or later." );
	script_xref( name: "URL", value: "https://www.paessler.com/prtg/history/preview" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "17.3.33.2654" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "17.3.33.2654" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

