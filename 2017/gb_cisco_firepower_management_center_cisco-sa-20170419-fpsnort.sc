CPE = "cpe:/a:cisco:firepower_management_center";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106778" );
	script_cve_id( "CVE-2016-6368" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_name( "Cisco Firepower Detection Engine Pragmatic General Multicast Protocol Decoding Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-fpsnort" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the detection engine parsing of Pragmatic General
  Multicast (PGM) protocol packets for Cisco Firepower System Software could allow an unauthenticated, remote
  attacker to cause a denial of service (DoS) condition due to the Snort process unexpectedly restarting." );
	script_tag( name: "insight", value: "The vulnerability is due to improper input validation of the fields in the
  PGM protocol packet. An attacker could exploit this vulnerability by sending a crafted PGM packet to the
  detection engine on the targeted device." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to cause a DoS condition if the Snort
  process restarts and traffic inspection is bypassed or traffic is dropped." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-05-06 01:29:00 +0000 (Sat, 06 May 2017)" );
	script_tag( name: "creation_date", value: "2017-04-20 15:59:29 +0200 (Thu, 20 Apr 2017)" );
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
affected = make_list( "6.0.0",
	 "6.0.0.0",
	 "6.0.0.1",
	 "6.0.1" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

