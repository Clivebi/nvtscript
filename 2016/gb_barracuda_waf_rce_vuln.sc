CPE = "cpe:/a:barracuda:web_application_firewall";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106150" );
	script_version( "2020-12-07T08:17:42+0000" );
	script_tag( name: "last_modification", value: "2020-12-07 08:17:42 +0000 (Mon, 07 Dec 2020)" );
	script_tag( name: "creation_date", value: "2016-07-25 12:59:46 +0700 (Mon, 25 Jul 2016)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Barracuda Web Application Firewall Remote Command Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "barracuda_web_application_firewall_detect.sc" );
	script_mandatory_keys( "barracuda_waf/installed" );
	script_tag( name: "summary", value: "Barracuda Web Application Firewall is prone to a remote code execution
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "By sending a specially crafted request an authenticated attacker may
  inject system commands while escalating to root do to relaxed sudo configurations on the appliances." );
	script_tag( name: "impact", value: "An authenticated attacker may execute arbitrary system commands." );
	script_tag( name: "affected", value: "Version <= 8.0.1.007." );
	script_tag( name: "solution", value: "Update to version 8.0.1.008 or later." );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/138020/Barracuda-Web-App-Firewall-Load-Balancer-Remote-Root.html" );
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
if(version_is_less_equal( version: version, test_version: "8.0.1.007" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.1.008" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

