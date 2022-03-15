CPE = "cpe:/a:zabbix:zabbix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106181" );
	script_version( "$Revision: 12096 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-08-17 11:04:27 +0700 (Wed, 17 Aug 2016)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:N" );
	script_cve_id( "CVE-2016-9140" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Zabbix Remote Code Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "zabbix_web_detect.sc" );
	script_mandatory_keys( "Zabbix/installed" );
	script_tag( name: "summary", value: "Zabbix is prone to a remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Zabbix is prone to an authenticated remote code execution vulnerability
in api_jsonrpc.php." );
	script_tag( name: "impact", value: "An authenticated attacker may execute arbitrary commands." );
	script_tag( name: "affected", value: "Zabbix version 2.2.x until 3.0.3" );
	script_tag( name: "solution", value: "Update to 3.0.4 or newer versions." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/39937/" );
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
if(version_in_range( version: version, test_version: "2.2.0", test_version2: "3.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.0.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

