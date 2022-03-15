CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105506" );
	script_cve_id( "CVE-2015-7393" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_name( "F5 BIG-IP - Privilege escalation vulnerability CVE-2015-7393" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K75136237" );
	script_tag( name: "impact", value: "A locally authenticated user with advanced shell (bash) access may be able to escalate privileges and gain administrative access. However, in order for a lower privilege user to exploit this vulnerability, the user account would need to be granted advanced shell (bash) access through manual modification of the Linux configuration files. This configuration is not supported on the affected F5 platforms." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The dcoep executable as shipped with BIG-IP versions 11.2.0 through 12.0.0 allows a local privilege escalation via undisclosed vectors to an authenticated local user." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "The remote host is missing a security patch." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-01-14 16:56:00 +0000 (Thu, 14 Jan 2016)" );
	script_tag( name: "creation_date", value: "2016-01-08 12:14:26 +0100 (Fri, 08 Jan 2016)" );
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
check_f5["LTM"] = make_array( "affected", "12.0.0;11.2.0-11.6.0;", "unaffected", "12.0.0_HF1;11.6.1;11.5.4;11.0.0-11.1.0;10.1.0-10.2.4;" );
check_f5["AAM"] = make_array( "affected", "12.0.0;11.4.0-11.6.0;", "unaffected", "12.0.0_HF1;11.6.1;11.5.4;" );
check_f5["AFM"] = make_array( "affected", "12.0.0;11.3.0-11.6.0;", "unaffected", "12.0.0_HF1;11.6.1;11.5.4;" );
check_f5["AVR"] = make_array( "affected", "12.0.0;11.2.0-11.6.0;", "unaffected", "12.0.0_HF1;11.6.1;11.5.4;11.0.0-11.1.0;" );
check_f5["APM"] = make_array( "affected", "12.0.0;11.2.0-11.6.0;", "unaffected", "12.0.0_HF1;11.6.1;11.5.4;11.0.0-11.1.0;10.1.0-10.2.4;" );
check_f5["ASM"] = make_array( "affected", "12.0.0;11.2.0-11.6.0;", "unaffected", "12.0.0_HF1;11.6.1;11.5.4;11.0.0-11.1.0;10.1.0-10.2.4;" );
check_f5["GTM"] = make_array( "affected", "11.2.0-11.6.0;", "unaffected", "11.6.1;11.5.4;11.0.0-11.1.0;10.1.0-10.2.4;" );
check_f5["LC"] = make_array( "affected", "12.0.0;11.2.0-11.6.0;", "unaffected", "12.0.0_HF1;11.6.1;11.5.4;11.0.0-11.1.0;10.1.0-10.2.4;" );
check_f5["PEM"] = make_array( "affected", "12.0.0;11.3.0-11.6.0;", "unaffected", "12.0.0_HF1;11.6.1;11.5.4;" );
check_f5["PSM"] = make_array( "affected", "11.2.0-11.4.1;", "unaffected", "11.0.0-11.1.0;10.1.0-10.2.4;" );
check_f5["WAM"] = make_array( "affected", "11.2.0-11.3.0;", "unaffected", "11.0.0-11.1.0;10.1.0-10.2.4;" );
check_f5["WOM"] = make_array( "affected", "11.2.0-11.3.0;", "unaffected", "11.0.0-11.1.0;10.1.0-10.2.4;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

