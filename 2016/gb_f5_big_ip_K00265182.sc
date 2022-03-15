CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105761" );
	script_cve_id( "CVE-2016-5020" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_version( "2021-05-03T13:21:59+0000" );
	script_name( "F5 BIG-IP - Custom monitor privilege escalation vulnerability CVE-2016-5020" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K00265182" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A user role assigned the Resource Administrator is capable of a privilege escalation which allows through the use of malicious external EAV monitor scripts to modify user accounts." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-05-03 13:21:59 +0000 (Mon, 03 May 2021)" );
	script_tag( name: "creation_date", value: "2016-06-13 11:42:13 +0200 (Mon, 13 Jun 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "F5 Local Security Checks" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_f5_big_ip_version.sc" );
	script_mandatory_keys( "f5/big_ip/version", "f5/big_ip/active_modules" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
require("list_array_func.inc.sc");
require("f5.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
check_f5["LTM"] = make_array( "affected", "12.0.0;11.4.0-11.6.1;11.2.1;10.2.1-10.2.4;", "unaffected", "12.1.0;12.0.0_HF3;" );
check_f5["AAM"] = make_array( "affected", "12.0.0-12.1.0;11.4.0-11.6.1;", "unaffected", "12.1.0;12.0.0_HF3;" );
check_f5["AFM"] = make_array( "affected", "12.0.0;11.4.0-11.6.1;", "unaffected", "12.1.0;12.0.0_HF3;" );
check_f5["AVR"] = make_array( "affected", "12.0.0;11.4.0-11.6.1;11.2.1;", "unaffected", "12.1.0;12.0.0_HF3;" );
check_f5["APM"] = make_array( "affected", "12.0.0;11.4.0-11.6.1;11.2.1;10.2.1-10.2.4;", "unaffected", "12.1.0;12.0.0_HF3;" );
check_f5["ASM"] = make_array( "affected", "12.0.0;11.4.0-11.6.1;11.2.1;10.2.1-10.2.4;", "unaffected", "12.1.0;12.0.0_HF3;" );
check_f5["LC"] = make_array( "affected", "12.0.0;11.4.0-11.6.1;11.2.1;10.2.1-10.2.4;", "unaffected", "12.1.0;12.0.0_HF3;" );
check_f5["PEM"] = make_array( "affected", "12.0.0;11.4.0-11.6.1;", "unaffected", "12.1.0;12.0.0_HF3;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

