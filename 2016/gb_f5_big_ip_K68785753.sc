CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140080" );
	script_cve_id( "CVE-2015-8898" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_name( "F5 BIG-IP - ImageMagick vulnerability CVE-2015-8898" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K68785753" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "ImageMagick vulnerability CVE-2015-8898" );
	script_tag( name: "impact", value: "BIG-IP systems that use a WebAcceleration profile configured with the Image Optimization settings (BIG-IP AAM and BIG-IP WebAccelerator) are vulnerable to this issue. An attacker using specially crafted image format files could cause memory corruption and, potentially, run arbitrary code with restricted user privileges, resulting in a denial- of -service (DoS) attack or an application restart." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-18 01:29:00 +0000 (Fri, 18 May 2018)" );
	script_tag( name: "creation_date", value: "2016-11-29 09:59:41 +0100 (Tue, 29 Nov 2016)" );
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
check_f5["WAM"] = make_array( "affected", "11.2.1;", "unaffected", "10.2.1-10.2.4;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

