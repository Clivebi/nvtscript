CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105363" );
	script_cve_id( "CVE-2015-1790" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "2021-05-03T13:21:59+0000" );
	script_name( "F5 BIG-IP - PKCS #7 vulnerability CVE-2015-1790" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K16898" );
	script_tag( name: "impact", value: "An attacker may be able to craft malformed ASN.1-encoded PKCS#7 blobs with missing content and trigger a NULL pointer dereference on parsing.Note: This vulnerability is exploitable only through the BIG-IP control plane (non-Traffic Management Microkernel (TMM) related tasks)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The PKCS7_dataDecodefunction in crypto/pkcs7/pk7_doit.c in OpenSSL before 0.9.8zg, 1.0.0 before 1.0.0s, 1.0.1 before 1.0.1n, and 1.0.2 before 1.0.2b allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) via a PKCS#7 blob that uses ASN.1 encoding and lacks inner EncryptedContent data. (CVE-2015-1790)" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "The remote host is missing a security patch." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-05-03 13:21:59 +0000 (Mon, 03 May 2021)" );
	script_tag( name: "creation_date", value: "2015-09-18 15:02:10 +0200 (Fri, 18 Sep 2015)" );
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
check_f5["LTM"] = make_array( "affected", "11.0.0-11.6.0;10.0.0-10.2.4;", "unaffected", "12.0.0;" );
check_f5["AAM"] = make_array( "affected", "11.4.0-11.6.0;", "unaffected", "12.0.0;" );
check_f5["AFM"] = make_array( "affected", "11.3.0-11.6.0;", "unaffected", "12.0.0;" );
check_f5["AVR"] = make_array( "affected", "11.0.0-11.6.0;", "unaffected", "12.0.0;" );
check_f5["APM"] = make_array( "affected", "11.0.0-11.6.0;10.1.0-10.2.4;", "unaffected", "12.0.0;" );
check_f5["ASM"] = make_array( "affected", "11.0.0-11.6.0;10.0.0-10.2.4;", "unaffected", "12.0.0;" );
check_f5["LC"] = make_array( "affected", "11.0.0-11.6.0;10.0.0-10.2.4;", "unaffected", "12.0.0;" );
check_f5["PEM"] = make_array( "affected", "11.3.0-11.6.0;", "unaffected", "12.0.0;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

