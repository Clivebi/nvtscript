CPE = "cpe:/h:cisco:email_security_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105777" );
	script_cve_id( "CVE-2016-1438" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_version( "$Revision: 12338 $" );
	script_name( "Cisco Email Security Appliance .zip File Scanning Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160622-esa" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to improper handling of content in .zip files. An attacker could exploit this vulnerability by sending a malicious .zip file that contains embedded executable content, which could be used to cause additional harm to the system." );
	script_tag( name: "solution", value: "See Vendor advisory." );
	script_tag( name: "summary", value: "A vulnerability in the anti-spam filter of the Cisco Email Security Appliance (ESA) could allow an unauthenticated, remote attacker to bypass anti-spam filtering functionality on an affected system." );
	script_tag( name: "affected", value: "This vulnerability affects Cisco Email Security Appliance Release 9.7.0-125." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-06-27 10:53:18 +0200 (Mon, 27 Jun 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_esa_version.sc" );
	script_mandatory_keys( "cisco_esa/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version == "9.7.0-125"){
	fix = "See advisory";
}
if(fix){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

