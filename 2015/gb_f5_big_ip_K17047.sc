CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105338" );
	script_cve_id( "CVE-2015-5058" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2021-05-05T11:50:38+0000" );
	script_name( "F5 BIG-IP - ICMP packet processing vulnerability CVE-2015-5058" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K17047" );
	script_tag( name: "impact", value: "A remote attacker may be able to cause a memory leak on the BIG-IP system." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Memory leak in the virtual server component in F5 Big-IP LTM, AAM, AFM, Analytics, APM, ASM, GTM, Link Controller, and PEM 11.5.x before 11.5.1 HF10, 11.5.3
before HF1, and 11.6.0 before HF5, BIG-IQ Cloud, Device, and Security 4.4.0 through 4.5.0, and BIG-IQ ADC 4.5.0 allows remote attackers to cause a denial of service (memory consumption) via a
large number of crafted ICMP packets." );
	script_tag( name: "solution", value: "Vendor Updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "F5 BIG-IP is prone to a ICMP packet processing vulnerability" );
	script_tag( name: "last_modification", value: "2021-05-05 11:50:38 +0000 (Wed, 05 May 2021)" );
	script_tag( name: "creation_date", value: "2015-08-31 11:23:51 +0200 (Mon, 31 Aug 2015)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
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
check_f5["LTM"] = make_array( "affected", "11.5.0-11.6.0;", "unaffected", "12.0.0;11.6.0_HF5;11.5.4;11.5.3_HF1;11.5.1_HF10;10.1.0-11.4.1;" );
check_f5["AAM"] = make_array( "affected", "11.5.0-11.6.0;", "unaffected", "12.0.0;11.6.0_HF5;11.5.4;11.5.3_HF1;11.5.1_HF10;11.4.0-11.4.1;" );
check_f5["AFM"] = make_array( "affected", "11.5.0-11.6.0;", "unaffected", "12.0.0;11.6.0_HF5;11.5.4;11.5.3_HF1;11.5.1_HF10;11.3.0-11.4.1;" );
check_f5["AVR"] = make_array( "affected", "11.5.0-11.6.0;", "unaffected", "12.0.0;11.6.0_HF5;11.5.4;11.5.3_HF1;11.5.1_HF10;11.0.0-11.4.1;" );
check_f5["APM"] = make_array( "affected", "11.5.0-11.6.0;", "unaffected", "12.0.0;11.6.0_HF5;11.5.4;11.5.3_HF1;11.5.1_HF10;10.1.0-11.4.1;" );
check_f5["ASM"] = make_array( "affected", "11.5.0-11.6.0;", "unaffected", "12.0.0;11.6.0_HF5;11.5.4;11.5.3_HF1;11.5.1_HF10;10.1.0-11.4.1;" );
check_f5["GTM"] = make_array( "affected", "11.5.0-11.6.0;", "unaffected", "11.6.0_HF5;11.5.4;11.5.3_HF1;11.5.1_HF10;10.1.0-11.4.1;" );
check_f5["LC"] = make_array( "affected", "11.5.0-11.6.0;", "unaffected", "12.0.0;11.6.0_HF5;11.5.4;11.5.3_HF1;11.5.1_HF10;10.1.0-11.4.1;" );
check_f5["PEM"] = make_array( "affected", "11.5.0-11.6.0;", "unaffected", "12.0.0;11.6.0_HF5;11.5.4;11.5.3_HF1;11.5.1_HF10;11.3.0-11.4.1;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

