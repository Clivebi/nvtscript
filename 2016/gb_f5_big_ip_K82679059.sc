CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105607" );
	script_cve_id( "CVE-2016-3686" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_name( "F5 BIG-IP - BIG-IP APM SSO vulnerability CVE-2016-3686" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K82679059" );
	script_tag( name: "impact", value: "There is a theoretical risk that a user could obtain unauthorized access to the system, causing a security breach." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Cleartext SessionID is visible in URL query parameters under some conditions." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "The remote host is missing a security patch." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-04-18 14:26:00 +0000 (Mon, 18 Apr 2016)" );
	script_tag( name: "creation_date", value: "2016-04-18 11:30:39 +0200 (Mon, 18 Apr 2016)" );
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
check_f5["APM"] = make_array( "affected", "11.0.0-11.6.0;", "unaffected", "12.0.0;11.6.0_HF6;10.1.0-10.2.4;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

