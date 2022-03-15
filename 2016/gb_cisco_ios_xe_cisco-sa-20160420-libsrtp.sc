CPE = "cpe:/o:cisco:ios_xe";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105661" );
	script_cve_id( "CVE-2015-6360" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2021-01-26T03:06:23+0000" );
	script_name( "Multiple Cisco Products libSRTP Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-libsrtp" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "Cisco released version 1.5.3 of the Secure Real-Time Transport Protocol (SRTP)
  library (libSRTP), which addresses a denial of service (DoS) vulnerability. Multiple Cisco products incorporate a vulnerable version of the libSRTP library.

  The vulnerability is in the encryption processing subsystem of libSRTP and could allow an unauthenticated,
  remote attacker to trigger a DoS condition. The vulnerability is due to improper input validation of certain fields of SRTP packets.
  An attacker could exploit this vulnerability by sending a crafted SRTP packet designed to trigger the issue to an affected device.

  The impact of this vulnerability on Cisco products may vary depending on the affected product. Details about the impact on each product
  are outlined in the `Conditions` section of each Cisco bug for this vulnerability. The bug IDs are listed at the top of this advisory and in the table in Vulnerable Products." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-01-26 03:06:23 +0000 (Tue, 26 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-05-09 17:29:13 +0200 (Mon, 09 May 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ios_xe_consolidation.sc" );
	script_mandatory_keys( "cisco/ios_xe/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
affected = make_list( "3.10.0S",
	 "3.10.1S",
	 "3.10.1xb.S",
	 "3.10.2S",
	 "3.10.2t.S",
	 "3.10.4S",
	 "3.10.5S",
	 "3.10.6S",
	 "3.10.7S",
	 "3.11.0S",
	 "3.11.1S",
	 "3.11.2S",
	 "3.11.3S",
	 "3.11.4S",
	 "3.13.0S",
	 "3.13.1S",
	 "3.13.4S",
	 "3.14.0S",
	 "3.15.1S",
	 "3.15.2S" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

