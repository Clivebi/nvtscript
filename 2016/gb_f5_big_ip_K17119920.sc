CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140056" );
	script_cve_id( "CVE-2016-7472" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "2021-09-20T14:01:48+0000" );
	script_name( "F5 BIG-IP - BIG-IP ASM Proactive Bot Defense vulnerability CVE-2016-7472" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K17119920" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "When Proactive Bot Defense is configured, BIG-IP ASM 12.1.0 and 12.1.1 systems may allow remote attackers to cause a denial of service (DoS) via a crafted HTTP header. (CVE-2016-7472)" );
	script_tag( name: "impact", value: "The BIG-IP ASM system may temporarily fail to process traffic as it recovers from the Traffic Management Microkernel (TMM) restarting, and failover may occur if you've configured the system as part of a high availability (HA) group." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-20 14:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-10 13:11:00 +0000 (Thu, 10 May 2018)" );
	script_tag( name: "creation_date", value: "2016-11-14 14:09:42 +0100 (Mon, 14 Nov 2016)" );
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
check_f5["ASM"] = make_array( "affected", "12.1.0-12.1.1;", "unaffected", "12.1.1_HF1;12.0.0;11.4.0-11.6.1;11.2.1;10.2.1-10.2.4;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

