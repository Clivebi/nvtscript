CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140098" );
	script_cve_id( "CVE-2016-5418" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_version( "2021-05-03T09:49:47+0000" );
	script_name( "F5 BIG-IP - libarchive vulnerability CVE-2016-5418" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K35246595" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "The sandboxing code in libarchive 3.2.0 and earlier mishandles hardlink archive entries of non-zero data size, which might allow remote attackers to write to arbitrary files via a crafted archive file." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-05-03 09:49:47 +0000 (Mon, 03 May 2021)" );
	script_tag( name: "creation_date", value: "2016-12-14 12:34:06 +0100 (Wed, 14 Dec 2016)" );
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
check_f5["LTM"] = make_array( "affected", "12.0.0-12.1.1;11.6.0-11.6.1;", "unaffected", "11.4.1-11.5.4;11.2.1;10.2.1-10.2.4;" );
check_f5["AAM"] = make_array( "affected", "12.0.0-12.1.1;11.6.0-11.6.1;", "unaffected", "11.4.1-11.5.4;" );
check_f5["AFM"] = make_array( "affected", "12.0.0-12.1.1;11.6.0-11.6.1;", "unaffected", "11.4.1-11.5.4;" );
check_f5["AVR"] = make_array( "affected", "12.0.0-12.1.1;11.6.0-11.6.1;", "unaffected", "11.4.1-11.5.4;11.2.1;" );
check_f5["APM"] = make_array( "affected", "12.0.0-12.1.1;11.6.0-11.6.1;", "unaffected", "11.4.1-11.5.4;11.2.1;10.2.1-10.2.4;" );
check_f5["ASM"] = make_array( "affected", "12.0.0-12.1.1;11.6.0-11.6.1;", "unaffected", "11.4.1-11.5.4;11.2.1;10.2.1-10.2.4;" );
check_f5["GTM"] = make_array( "affected", "11.6.0-11.6.1;", "unaffected", "11.4.1-11.5.4;11.2.1;10.2.1-10.2.4;" );
check_f5["LC"] = make_array( "affected", "12.0.0-12.1.1;11.6.0-11.6.1;", "unaffected", "11.4.1-11.5.4;11.2.1;10.2.1-10.2.4;" );
check_f5["PEM"] = make_array( "affected", "12.0.0-12.1.1;11.6.0-11.6.1;", "unaffected", "11.4.1-11.5.4;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

