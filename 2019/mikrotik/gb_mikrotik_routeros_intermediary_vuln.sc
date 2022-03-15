CPE = "cpe:/o:mikrotik:routeros";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142020" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-21 13:08:45 +0700 (Thu, 21 Feb 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:49:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2019-3924" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MikroTik RouterOS Intermediary Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mikrotik_router_routeros_consolidation.sc" );
	script_mandatory_keys( "mikrotik/detected" );
	script_tag( name: "summary", value: "MikroTik RouterOS is vulnerable to an intermediary vulnerability. The software
will execute user defined network requests to both WAN and LAN clients. A remote unauthenticated attacker can use
this vulnerability to bypass the router's firewall or for general network scanning activities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "MikroTik RouterOS prior to version 6.42.12 and 6.43.12." );
	script_tag( name: "solution", value: "Update to version 6.42.1, 6.43.12 or later." );
	script_xref( name: "URL", value: "https://mikrotik.com/download/changelogs/bugfix-release-tree" );
	script_xref( name: "URL", value: "https://mikrotik.com/download/changelogs/release-candidate-release-tree" );
	script_xref( name: "URL", value: "https://www.tenable.com/security/research/tra-2019-07" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "6.42.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.42.12" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.43", test_version2: "6.43.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.43.12" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

