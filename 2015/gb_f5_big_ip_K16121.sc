CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105220" );
	script_cve_id( "CVE-2014-8727" );
	script_tag( name: "cvss_base", value: "6.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:S/C:N/I:C/A:C" );
	script_version( "2021-05-05T11:50:38+0000" );
	script_name( "F5 BIG-IP - Directory traversal vulnerability CVE-2014-8727" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K16121" );
	script_tag( name: "impact", value: "An attacker with Resource Administrator or Administrator role access to the BIG-IP
Configuration utility may be able to delete arbitrary files." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple directory traversal vulnerabilities in F5 BIG-IP before 10.2.2 allow local users with
the 'Resource Administrator' or 'Administrator' role to enumerate and delete arbitrary files via a .. (dot dot) in the name parameter
to (1) tmui/Control/jspmap/tmui/system/archive/properties.jsp or (2) tmui/Control/form." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "F5 BIG-IP is prone to a directory traversal vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-05-05 11:50:38 +0000 (Wed, 05 May 2021)" );
	script_tag( name: "creation_date", value: "2015-02-17 08:08:36 +0100 (Tue, 17 Feb 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "F5 Local Security Checks" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
check_f5["LTM"] = make_array( "affected", "10.0.0-10.2.2_HF1;", "unaffected", "11.0.0-11.6.0;10.2.2_HF2-10.2.4;" );
check_f5["APM"] = make_array( "affected", "10.1.0-10.2.2_HF1;", "unaffected", "11.0.0-11.6.0;10.2.2_HF2-10.2.4;" );
check_f5["ASM"] = make_array( "affected", "10.0.0-10.2.2_HF1;", "unaffected", "11.0.0-11.6.0;10.2.2_HF2-10.2.4;" );
check_f5["GTM"] = make_array( "affected", "10.0.0-10.2.2_HF1;", "unaffected", "11.0.0-11.6.0;10.2.2_HF2-10.2.4;" );
check_f5["LC"] = make_array( "affected", "10.0.0-10.2.2_HF1;", "unaffected", "11.0.0-11.6.0;10.2.2_HF2-10.2.4;" );
check_f5["PSM"] = make_array( "affected", "10.0.0-10.2.2_HF1;", "unaffected", "11.0.0-11.4.1;10.2.2_HF2-10.2.4;" );
check_f5["WAM"] = make_array( "affected", "10.0.0-10.2.2_HF1;", "unaffected", "11.0.0-11.3.0;10.2.2_HF2-10.2.4;" );
check_f5["WOM"] = make_array( "affected", "10.0.0-10.2.2_HF1;", "unaffected", "11.0.0-11.3.0;10.2.2_HF2-10.2.4;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

