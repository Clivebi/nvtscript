CPE = "cpe:/o:cisco:nx-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106340" );
	script_cve_id( "CVE-2016-1453" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_name( "Cisco Nexus 7000 and 7700 Series Switches Overlay Transport Virtualization Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-otv" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to 7.2(2)D1(1) or later." );
	script_tag( name: "summary", value: "A vulnerability in the Overlay Transport Virtualization (OTV) generic
routing encapsulation (GRE) implementation of the Cisco Nexus 7000 and 7700 Series Switches could allow an
unauthenticated, adjacent attacker to cause a reload of the affected system or to remotely execute code." );
	script_tag( name: "insight", value: "The vulnerability is due to incomplete input validation performed on the
size of OTV packet header parameters, which can result in a buffer overflow. An attacker could exploit this
vulnerability by sending a crafted OTV UDP packet to the OTV interface on an affected device." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to execute arbitrary code and obtain
full control of the system or cause a reload of the OTV related process on the affected device." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)" );
	script_tag( name: "creation_date", value: "2016-10-06 11:57:56 +0700 (Thu, 06 Oct 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_nx_os_version.sc" );
	script_mandatory_keys( "cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(!device = get_kb_item( "cisco_nx_os/device" )){
	exit( 0 );
}
if(!ContainsString( device, "Nexus" )){
	exit( 0 );
}
if(!nx_model = get_kb_item( "cisco_nx_os/model" )){
	exit( 0 );
}
if(IsMatchRegexp( nx_model, "^7[0-9]+" )){
	affected = make_list( "4.1.(2)",
		 "4.1.(3)",
		 "4.1.(4)",
		 "4.1.(5)",
		 "4.2(3)",
		 "4.2(4)",
		 "4.2(6)",
		 "4.2(8)",
		 "4.2.(2a)",
		 "5.0(2a)",
		 "5.0(3)",
		 "5.0(5)",
		 "5.1(1)",
		 "5.1(1a)",
		 "5.1(3)",
		 "5.1(4)",
		 "5.1(5)",
		 "5.1(6)",
		 "5.2(1)",
		 "5.2(3a)",
		 "5.2(4)",
		 "5.2(5)",
		 "5.2(7)",
		 "5.2(9)",
		 "6.0(1)",
		 "6.0(2)",
		 "6.0(3)",
		 "6.0(4)",
		 "6.1(1)",
		 "6.1(2)",
		 "6.1(3)",
		 "6.1(4)",
		 "6.1(4a)",
		 "6.1(5)",
		 "6.2(10)",
		 "6.2(12)",
		 "6.2(14)S1",
		 "6.2(2)",
		 "6.2(2a)",
		 "6.2(6)",
		 "6.2(6b)",
		 "6.2(8)",
		 "6.2(8a)",
		 "6.2(8b)",
		 "7.2(0)N1(0.1)" );
}
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "7.2(2)D1(1)" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

