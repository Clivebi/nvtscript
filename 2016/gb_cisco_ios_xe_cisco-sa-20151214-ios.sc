CPE = "cpe:/o:cisco:ios_xe";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105676" );
	script_cve_id( "CVE-2015-6359" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2021-01-26T03:06:23+0000" );
	script_name( "Cisco IOS XE Software IPv6 Neighbor Discovery Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151214-ios" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Cisco has released software updates that address these vulnerabilities. Workarounds that
  mitigate these vulnerabilities are available." );
	script_tag( name: "summary", value: "A vulnerability in the IPv6 neighbor discovery (ND) handling of Cisco IOS XE Software on
  ASR platforms could allow an unauthenticated, adjacent attacker to cause an affected device to crash." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient bounds on internal tables. An attacker could exploit this
  vulnerability by flooding an adjacent IOS XE device with specific ND messages." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to deplete the available memory, possibly causing an affected device to crash." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-01-26 03:06:23 +0000 (Tue, 26 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-05-10 10:49:56 +0200 (Tue, 10 May 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ios_xe_consolidation.sc" );
	script_mandatory_keys( "cisco/ios_xe/detected", "cisco/ios_xe/model" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(!model = get_kb_item( "cisco/ios_xe/model" )){
	exit( 0 );
}
if(!IsMatchRegexp( model, "^ASR" )){
	exit( 99 );
}
affected = make_list( "3.14.0S",
	 "3.14.1S",
	 "3.14.2S",
	 "3.14.3S",
	 "3.14.4S",
	 "3.15.0S",
	 "3.15.1S",
	 "3.16.0S" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

