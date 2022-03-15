CPE = "cpe:/o:cisco:ios_xe";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106310" );
	script_cve_id( "CVE-2016-6379" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2021-01-26T03:06:23+0000" );
	script_name( "Cisco IOS XE Software IP Detail Record Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-ipdr" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the IP Detail Record (IPDR) code of Cisco IOS XE
Software could allow an unauthenticated, remote attacker to cause an affected system to reload." );
	script_tag( name: "insight", value: "The vulnerability is due to improper handling of IPDR packets. An
attacker could exploit this vulnerability by sending crafted IPDR packets to an affected system." );
	script_tag( name: "impact", value: "A successful exploit could cause the device to reload, resulting in a
denial of service (DoS) condition." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-01-26 03:06:23 +0000 (Tue, 26 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-09-29 15:22:06 +0700 (Thu, 29 Sep 2016)" );
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
affected = make_list( "3.14.0S",
	 "3.14.1S",
	 "3.14.2S",
	 "3.14.3S",
	 "3.14.4S",
	 "3.15.1c.S",
	 "3.15.3S",
	 "3.15.4S",
	 "3.15.0S",
	 "3.15.1S",
	 "3.15.2S",
	 "16.1.3",
	 "16.1.1",
	 "16.1.2",
	 "3.16.0S",
	 "3.16.0c.S" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

