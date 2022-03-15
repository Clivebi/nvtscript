CPE = "cpe:/a:cisco:firesight_management_center";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106231" );
	script_cve_id( "CVE-2016-6395" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco FireSIGHT System Software Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160907-fsss" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the web-based management interface of Cisco FireSIGHT
System Software could allow an authenticated, remote attacker to conduct a cross-site scripting (XSS) attack
against a user of the web-based management interface of an affected device.

The vulnerability is due to insufficient validation of user-supplied input by the web-based management interface
of an affected device. An attacker could exploit this vulnerability by persuading a user of the interface to
click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the
context of the interface or allow the attacker to access sensitive browser-based information.

Cisco has released software updates that address this vulnerability. There are no workarounds that address
this vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-09-08 10:15:39 +0700 (Thu, 08 Sep 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_firesight_management_center_version.sc", "gb_cisco_firesight_management_center_http_detect.sc" );
	script_mandatory_keys( "cisco_firesight_management_center/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
affected = make_list( "5.1.0",
	 "5.1.0.1",
	 "5.1.0.2",
	 "5.1.0.3",
	 "5.1.1",
	 "5.1.1.1",
	 "5.1.1.2",
	 "5.1.1.3",
	 "5.1.1.4",
	 "5.1.1,5",
	 "5.1.1.6",
	 "5.1.1.8",
	 "5.1.1.9",
	 "5.1.1.10",
	 "5.1.1.11",
	 "5.2.0",
	 "5.2.0.1",
	 "5.2.0.2",
	 "5.2.0.3",
	 "5.2.0.4",
	 "5.2.0.5",
	 "5.2.0.6",
	 "5.2.0.8",
	 "5.3.0",
	 "5.3.0.1",
	 "5.3.0.2",
	 "5.3.0.3",
	 "5.3.0.4",
	 "5.3.0.5",
	 "5.3.0.6",
	 "5.3.0.7",
	 "5.3.1.1",
	 "5.3.1.2",
	 "5.3.1.3",
	 "5.3.1",
	 "5.3.1.5",
	 "5.3.1.4",
	 "5.3.1.7",
	 "5.4.0",
	 "5.4.0.1",
	 "5.4.0.2",
	 "5.4.0.3",
	 "5.4.0.4",
	 "5.4.0.5",
	 "5.4.0.6",
	 "5.4.1",
	 "5.4.1.2",
	 "5.4.1.3",
	 "5.4.1.4",
	 "6.0.0",
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

