CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105374" );
	script_cve_id( "CVE-2014-0131" );
	script_tag( name: "cvss_base", value: "2.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:P/I:N/A:N" );
	script_version( "2021-05-03T13:21:59+0000" );
	script_name( "F5 BIG-IP - Linux kernel vulnerability CVE-2014-0131" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K15699" );
	script_tag( name: "impact", value: "Attackers may be able to obtain sensitive information from kernel memory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Use-after-free vulnerability in the skb_segment function in net/core/skbuff.c in the Linux kernel through 3.13.6 allows attackers to obtain sensitive information from kernel memory by leveraging the absence of a certain orphaning operation. (CVE-2014-0131)" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "The remote host is missing a security patch." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-05-03 13:21:59 +0000 (Mon, 03 May 2021)" );
	script_tag( name: "creation_date", value: "2015-09-19 10:41:51 +0200 (Sat, 19 Sep 2015)" );
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
check_f5["LTM"] = make_array( "affected", "11.1.0-11.6.0;", "unaffected", "11.0.0;10.0.0-10.2.4;" );
check_f5["AVR"] = make_array( "affected", "11.1.0-11.6.0;", "unaffected", "11.0.0;" );
check_f5["APM"] = make_array( "affected", "11.1.0-11.6.0;", "unaffected", "11.0.0;10.1.0-10.2.4;" );
check_f5["ASM"] = make_array( "affected", "11.1.0-11.6.0;", "unaffected", "11.0.0;10.0.0-10.2.4;" );
check_f5["GTM"] = make_array( "affected", "11.1.0-11.6.0;", "unaffected", "11.0.0;10.0.0-10.2.4;" );
check_f5["LC"] = make_array( "affected", "11.1.0-11.6.0;", "unaffected", "11.0.0;10.0.0-10.2.4;" );
check_f5["PSM"] = make_array( "affected", "11.1.0-11.4.1;", "unaffected", "11.0.0;10.0.0-10.2.4;" );
check_f5["WAM"] = make_array( "affected", "11.1.0-11.3.0;", "unaffected", "11.0.0;10.0.0-10.2.4;" );
check_f5["WOM"] = make_array( "affected", "11.1.0-11.3.0;", "unaffected", "11.0.0;10.0.0-10.2.4;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

