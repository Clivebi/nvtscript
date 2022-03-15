CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140223" );
	script_cve_id( "CVE-2016-7467", "CVE-2016-9244" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_name( "F5 BIG-IP - TMM SSO plugin vulnerability CVE-2016-7467" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K95444512" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "Traffic may be disrupted or failover initiated when a malformed, signed SAML authentication request from an authenticated user is sent via SP connector on a BIG-IP configured as a SAML Identity Provider." );
	script_tag( name: "impact", value: "When the system is exploited, traffic is temporarily disrupted while services restart." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-06 15:11:00 +0000 (Thu, 06 Jun 2019)" );
	script_tag( name: "creation_date", value: "2017-03-27 12:44:20 +0200 (Mon, 27 Mar 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "F5 Local Security Checks" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
check_f5["APM"] = make_array( "affected", "12.0.0-12.1.1;11.6.0-11.6.1_HF1;11.5.4-11.5.4_HF2;", "unaffected", "12.1.2;11.6.1_HF2;11.5.4_HF3;11.4.0-11.5.3;11.2.1;10.2.1-10.2.4;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

