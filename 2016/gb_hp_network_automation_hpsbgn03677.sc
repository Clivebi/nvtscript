CPE = "cpe:/a:hp:network_automation";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106430" );
	script_version( "2021-09-09T08:52:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 08:52:50 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-12-01 11:55:23 +0700 (Thu, 01 Dec 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2016-8511" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "HP Network Automation RCE Vulnerability (HPSBGN03677)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_hp_microfocus_network_automation_http_detect.sc" );
	script_mandatory_keys( "microfocus/network_automation/detected" );
	script_tag( name: "summary", value: "HP Network Automation is prone to a remote code execution (RCE)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Potential security vulnerabilities in RPCServlet and Java
  deserialization were addressed by HPE Network Automation. The vulnerabilities could be remotely
  exploited to allow code execution." );
	script_tag( name: "impact", value: "An attacker may execute arbitrary code." );
	script_tag( name: "affected", value: "HP Network Automation Software v9.1x, v9.2x, v10.00, v10.00.01,
  v10.00.02, v10.10, v10.11, v10.11.01, v10.20." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-c05344849" );
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
if(version_is_less_equal( version: version, test_version: "10.00" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.00.021" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version == "10.10"){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.11" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version == "10.11"){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.11.011" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version == "10.20"){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.20.001" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

