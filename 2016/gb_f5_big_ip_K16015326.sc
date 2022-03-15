CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105539" );
	script_cve_id( "CVE-2013-4397" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "2021-05-03T13:21:59+0000" );
	script_name( "F5 BIG-IP - libtar vulnerability CVE-2013-4397" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K16015326" );
	script_tag( name: "impact", value: "A remote attacker may be able to cause a denial-of-service (DoS) or execute arbitrary code on the BIG-IP system." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple integer overflows in the th_read function in lib/block.c in libtar before 1.2.20 allow remote attackers to cause a denial of service (crash) and possibly execute arbitrary code via a long (1) name or (2) link in an archive, which triggers a heap-based buffer overflow." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "The remote host is missing a security patch." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-05-03 13:21:59 +0000 (Mon, 03 May 2021)" );
	script_tag( name: "creation_date", value: "2016-02-11 18:30:55 +0100 (Thu, 11 Feb 2016)" );
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
check_f5["LTM"] = make_array( "affected", "11.6.0;11.4.0-11.5.4;", "unaffected", "12.0.0;11.6.1_HF1;11.5.4_HF2;11.2.1;10.1.0-10.2.4;" );
check_f5["AAM"] = make_array( "affected", "11.6.0;11.4.0-11.5.4;", "unaffected", "12.0.0;11.6.1_HF1;11.5.4_HF2;11.2.1;10.1.0-10.2.4;" );
check_f5["AFM"] = make_array( "affected", "11.6.0;11.3.0-11.5.4;", "unaffected", "12.0.0;11.6.1_HF1;11.5.4_HF2;11.2.1;10.1.0-10.2.4;" );
check_f5["AVR"] = make_array( "affected", "11.6.0;11.4.0-11.5.4;", "unaffected", "12.0.0;11.6.1_HF1;11.5.4_HF2;11.2.1;10.1.0-10.2.4;" );
check_f5["APM"] = make_array( "affected", "11.6.0;11.4.0-11.5.4;", "unaffected", "12.0.0;11.6.1_HF1;11.5.4_HF2;11.2.1;10.1.0-10.2.4;" );
check_f5["ASM"] = make_array( "affected", "11.6.0;11.4.0-11.5.4;", "unaffected", "12.0.0;11.6.1_HF1;11.5.4_HF2;11.2.1;10.1.0-10.2.4;" );
check_f5["GTM"] = make_array( "affected", "11.6.0;11.4.0-11.5.4;", "unaffected", "11.6.1_HF1;11.5.4_HF2;11.2.1;10.1.0-10.2.4;" );
check_f5["LC"] = make_array( "affected", "11.6.0;11.4.0-11.5.4;", "unaffected", "12.0.0;11.6.1_HF1;11.5.4_HF2;11.2.1;10.1.0-10.2.4;" );
check_f5["PEM"] = make_array( "affected", "11.6.0;11.4.0-11.5.4;", "unaffected", "12.0.0;11.6.1_HF1;11.5.4_HF2;11.2.1;10.1.0-10.2.4;" );
check_f5["PSM"] = make_array( "affected", "11.4.0-11.4.1;11.0.0-11.2.0;", "unaffected", "11.2.1;10.1.0-10.2.4;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

