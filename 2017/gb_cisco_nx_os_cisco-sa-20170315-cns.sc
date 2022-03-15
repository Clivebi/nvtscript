CPE = "cpe:/o:cisco:nx-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106655" );
	script_cve_id( "CVE-2017-3875" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_version( "2021-09-10T13:01:42+0000" );
	script_name( "Cisco Nexus 7000 Series Switches Access-Control Filtering Mechanisms Bypass Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170315-cns" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in certain access-control filtering mechanisms on Cisco
Nexus 7000 Series Switches could allow an unauthenticated, remote attacker to bypass defined traffic configured
within an access control list (ACL) on the affected system." );
	script_tag( name: "insight", value: "The vulnerability is due to the device failing to inspect specific traffic
when other ACL checking mechanisms are in place. An attacker could exploit this vulnerability by issuing crafted
commands for which a particular ACL would not match defined traffic." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to bypass certain rulesets defined on a
Network Time Protocol (NTP) ACL." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-10 13:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-03-16 10:48:42 +0700 (Thu, 16 Mar 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_nx_os_version.sc" );
	script_mandatory_keys( "cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!device = get_kb_item( "cisco_nx_os/device" )){
	exit( 0 );
}
if(!ContainsString( device, "Nexus" )){
	exit( 0 );
}
if(!nx_model = get_kb_item( "cisco_nx_os/model" )){
	exit( 0 );
}
if(!IsMatchRegexp( nx_model, "^7" )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "5.2(4)",
	 "6.1(3)S5",
	 "6.1(3)S6",
	 "6.2(1.121)S0",
	 "7.2(1)D1(1)",
	 "7.3(0)ZN(0.161)",
	 "7.3(1)N1(0.1)" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

