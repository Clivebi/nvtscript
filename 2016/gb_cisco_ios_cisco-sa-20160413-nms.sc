CPE = "cpe:/o:cisco:ios";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106210" );
	script_cve_id( "CVE-2016-1378" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco Catalyst Switches Network Mobility Services Protocol Port Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160413-nms" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "Cisco Catalyst Switches running Cisco IOS Software releases prior
to 15.2(2)E1 may allow an unauthenticated, remote attacker to retrieve version information about the software
release running on the device by accessing the Network Mobility Services Protocol (NMSP) port.

The vulnerability is due to a failure to properly secure NMSP with authentication, which has been
made standard in Cisco IOS Software releases 15.2(2)E1 and later. An attacker could exploit earlier
software releases to map the network and gather information for further attacks.

Cisco has released software updates that address this vulnerability. Workarounds that address this
vulnerability are not available." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-08-26 13:05:32 +0700 (Fri, 26 Aug 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_cisco_ios_get_version.sc" );
	script_mandatory_keys( "cisco_ios/version", "cisco_ios/model" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!model = get_kb_item( "cisco_ios/model" )){
	exit( 0 );
}
if(!IsMatchRegexp( model, "^WS\\-C[0-9]" ) || IsMatchRegexp( model, "WS\\-C60" )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "15.1(1)SG",
	 "15.1(1)SG1",
	 "15.1(1)SG2",
	 "15.1(2)SG",
	 "15.1(2)SG1",
	 "15.1(2)SG2",
	 "15.1(2)SG3",
	 "15.1(2)SG4",
	 "15.1(2)SG5",
	 "15.1(2)SG6",
	 "15.1(2)SG7",
	 "15.1(1)SY",
	 "15.1(1)SY1",
	 "15.1(1)SY2",
	 "15.1(1)SY3",
	 "15.1(1)SY4",
	 "15.1(1)SY5",
	 "15.1(1)SY6",
	 "15.1(2)SY",
	 "15.1(2)SY1",
	 "15.1(2)SY2",
	 "15.1(2)SY3",
	 "15.1(2)SY4",
	 "15.1(2)SY4a",
	 "15.1(2)SY5",
	 "15.1(2)SY6",
	 "15.1(2)SY7",
	 "15.1(2)SY8" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

