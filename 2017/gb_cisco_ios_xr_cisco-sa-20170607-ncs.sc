CPE = "cpe:/o:cisco:ios_xr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106857" );
	script_cve_id( "CVE-2017-6666" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:N/A:P" );
	script_version( "2021-09-08T14:01:33+0000" );
	script_name( "Cisco Network Convergence System 5500 Series Routers Local Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170607-ncs" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the forwarding component of Cisco IOS XR Software for
Cisco Network Convergence System (NCS) 5500 Series Routers could allow an authenticated, local attacker to cause
the router to stop forwarding data traffic across Traffic Engineering (TE) tunnels, resulting in a denial of
service (DoS) condition." );
	script_tag( name: "insight", value: "The vulnerability occurs because adjacency information for a Traffic
Engineering (TE) tunnel's physical source interface is not propagated to hardware after the adjacency is lost.
This information needs to be relearned. An attacker could exploit this vulnerability by logging in to the
router's CLI with administrator privileges and issuing the clear arp-cache command." );
	script_tag( name: "impact", value: "A local attacker may cause a denial of service condition." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-08 14:01:33 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-08 11:35:21 +0700 (Thu, 08 Jun 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ios_xr_version.sc" );
	script_mandatory_keys( "cisco/ios_xr/version", "cisco/ios_xr/model" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!model = get_kb_item( "cisco/ios_xr/model" )){
	exit( 0 );
}
if(!ContainsString( model, "NCS-5500" )){
	exit( 99 );
}
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "6.0.0",
	 "6.0.1",
	 "6.1.0",
	 "6.1.1",
	 "6.1.2",
	 "6.1.3",
	 "6.2.0",
	 "6.2.1" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

