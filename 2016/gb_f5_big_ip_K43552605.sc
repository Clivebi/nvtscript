CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105505" );
	script_cve_id( "CVE-2015-8098" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_name( "F5 BIG-IP - Out-of-bounds memory vulnerability with the BIG-IP APM system CVE-2015-8098" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K43552605" );
	script_tag( name: "impact", value: "An unauthenticated remote attacker may be able to cause a denial-of-service (DoS) or perform remote code execution on an affected BIG-IP APM device." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An out-of-bounds memory vulnerability may allow an unauthenticated BIG-IP APM user to cause a denial-of-service (DoS) or possibly perform remote code execution on a BIG-IP system processing a Citrix Remote Desktop connection through a virtual server that is configured with remote desktop profile" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "The remote host is missing a security patch." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-01-15 00:10:00 +0000 (Fri, 15 Jan 2016)" );
	script_tag( name: "creation_date", value: "2016-01-08 11:49:44 +0100 (Fri, 08 Jan 2016)" );
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
check_f5["APM"] = make_array( "affected", "11.6.0-11.6.0_HF3;11.5.0-11.5.2_HF1;11.4.1-11.4.1_HF8;", "unaffected", "12.0.0;11.6.0_HF4-11.6.0_HF6;11.5.3;11.4.1_HF9;11.0.0-11.4.0;10.1.0-10.2.4;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

