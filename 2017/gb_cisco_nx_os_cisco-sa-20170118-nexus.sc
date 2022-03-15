CPE = "cpe:/o:cisco:nx-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106528" );
	script_cve_id( "CVE-2017-3804" );
	script_tag( name: "cvss_base", value: "5.7" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:N/I:N/A:C" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_name( "Cisco Nexus 5000, 6000, and 7000 Series Switches Software IS-IS Packet Processing Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170118-nexus" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in Intermediate System-to-Intermediate System (IS-IS)
protocol packet processing of Cisco Nexus 5000, 6000, and 7000 Series Switches software could allow an
unauthenticated, adjacent attacker to cause a reload of the affected device." );
	script_tag( name: "insight", value: "The vulnerability is due to improper processing of crafted IS-IS protocol
packets. An attacker could exploit this vulnerability by sending a crafted IS-IS protocol packet over an
established adjacency." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to cause a reload of the affected
device." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-01-19 11:24:12 +0700 (Thu, 19 Jan 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_nx_os_version.sc" );
	script_mandatory_keys( "cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
device = get_kb_item( "cisco_nx_os/device" );
if(!device || !ContainsString( device, "Nexus" )){
	exit( 0 );
}
model = get_kb_item( "cisco_nx_os/model" );
if(!model || !IsMatchRegexp( model, "^(5|6|7)[0-9]+" )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "7.1(3)N1(2.1)",
	 "7.1(3)N1(2.1)",
	 "7.1(3)N1(3.12)",
	 "7.1(3)N1(3.12)",
	 "7.3(2)N1(0.296)",
	 "7.3(2)N1(0.296)",
	 "8.0(1)S2",
	 "8.0(1)S2" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

