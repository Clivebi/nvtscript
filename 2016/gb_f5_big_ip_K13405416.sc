CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105504" );
	script_cve_id( "CVE-2012-3515" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-05-03T13:21:59+0000" );
	script_name( "F5 BIG-IP - QEMU vulnerability CVE-2012-3515" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K13405416" );
	script_tag( name: "impact", value: "An attacker may gain privileged access by using a crafted escape sequence." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Qemu, as used in Xen 4.0, 4.1 and possibly other products, when emulating certain devices with a virtual console backend, allows local OS guest users to gain privileges via a crafted escape VT100 sequence that triggers the overwrite of a 'device model's address space.'" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "The remote host is missing a security patch." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-05-03 13:21:59 +0000 (Mon, 03 May 2021)" );
	script_tag( name: "creation_date", value: "2016-01-08 11:38:32 +0100 (Fri, 08 Jan 2016)" );
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
check_f5["LTM"] = make_array( "affected", "11.0.0-11.2.1_HF14;", "unaffected", "12.0.0;11.3.0-11.6.0;11.2.1_HF15;10.1.0-10.2.4;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );
