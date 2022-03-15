CPE = "cpe:/a:cisco:firepower_management_center";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140272" );
	script_cve_id( "CVE-2017-6766" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_name( "Cisco Firepower Management Secure Sockets Layer Policy Bypass Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170802-fpw" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the Secure Sockets Layer (SSL) Decryption and Inspection
  feature of Cisco Firepower System Software could allow an unauthenticated, remote attacker to bypass the SSL
  policy for decrypting and inspecting traffic on an affected system." );
	script_tag( name: "insight", value: "The vulnerability is due to unexpected interaction with Known Key and Decrypt
  and Resign configuration settings of SSL policies when the affected software receives unexpected SSL packet
  headers. An attacker could exploit this vulnerability by sending a crafted SSL packet through an affected device
  in a valid SSL session." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to bypass the SSL decryption and
  inspection policy for the affected system, which could allow traffic to flow through the system without being
  inspected." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-08-03 10:19:50 +0700 (Thu, 03 Aug 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_firepower_management_center_consolidation.sc" );
	script_mandatory_keys( "cisco/firepower_management_center/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
affected = make_list( "5.4.0",
	 "5.4.1",
	 "6.0.0",
	 "6.1.0",
	 "6.2.0",
	 "6.2.1",
	 "6.2.2" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

