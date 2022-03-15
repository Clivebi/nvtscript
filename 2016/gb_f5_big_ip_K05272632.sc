CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105502" );
	script_cve_id( "CVE-2015-8611" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-05-10T09:20:28+0000" );
	script_name( "F5 BIG-IP - BIG-IP AOM password sync vulnerability CVE-2015-8611" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K05272632" );
	script_tag( name: "impact", value: "An Always-On Management (AOM) configuration with network access may allow access to AOM using a stale or default password." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "F5 BIG-IP systems on the 2000, 4000, 5000, 7000, and 10000 platforms may fail to sync passwords to the Always-On-Management (AOM)." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "The remote host is missing a security patch." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-05-10 09:20:28 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2016-01-08 11:30:30 +0100 (Fri, 08 Jan 2016)" );
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
check_f5["LTM"] = make_array( "affected", "12.0.0;", "unaffected", "12.1.0;12.0.0_HF1;11.0.0-11.6.0;10.1.0-10.2.4;" );
check_f5["AAM"] = make_array( "affected", "12.0.0;", "unaffected", "12.1.0;12.0.0_HF1;11.4.0-11.6.0;" );
check_f5["AFM"] = make_array( "affected", "12.0.0;", "unaffected", "12.1.0;12.0.0_HF1;11.3.0-11.6.0;" );
check_f5["AVR"] = make_array( "affected", "12.0.0;", "unaffected", "12.1.0;12.0.0_HF1;11.0.0-11.6.0;" );
check_f5["APM"] = make_array( "affected", "12.0.0;", "unaffected", "12.1.0;12.0.0_HF1;11.0.0-11.6.0;10.1.0-10.2.4;" );
check_f5["ASM"] = make_array( "affected", "12.0.0;", "unaffected", "12.1.0;12.0.0_HF1;11.0.0-11.6.0;10.1.0-10.2.4;" );
check_f5["LC"] = make_array( "affected", "12.0.0;", "unaffected", "12.1.0;12.0.0_HF1;11.0.0-11.6.0;10.1.0-10.2.4;" );
check_f5["PEM"] = make_array( "affected", "12.0.0;", "unaffected", "12.1.0;12.0.0_HF1;11.3.0-11.6.0;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

