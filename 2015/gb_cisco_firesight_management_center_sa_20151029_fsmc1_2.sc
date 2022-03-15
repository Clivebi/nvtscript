CPE = "cpe:/a:cisco:firesight_management_center";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105446" );
	script_cve_id( "CVE-2015-6354", "CVE-2015-6353" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_version( "$Revision: 12106 $" );
	script_name( "Cisco FireSIGHT Management Center Cross-Site Scripting / HTML Injection Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151029-fsmc1" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151029-fsmc2" );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by injecting malicious code into an affected parameter and convincing the user to access a web page that would trigger the rendering of the injected code." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to improper sanitization of parameter values." );
	script_tag( name: "solution", value: "See vendor advisory" );
	script_tag( name: "summary", value: "A vulnerability in the web interface of Cisco FireSIGHT Management Center (MC) could allow an authenticated, remote attacker to modify a page of the web interface." );
	script_tag( name: "affected", value: "See vendor advisory" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-11-10 11:48:58 +0100 (Tue, 10 Nov 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_firesight_management_center_version.sc", "gb_cisco_firesight_management_center_http_detect.sc" );
	script_mandatory_keys( "cisco_firesight_management_center/version" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version == "6.0.0" || version == "5.3.1.5" || version == "5.4.1.3"){
	report = "Installed version: " + version + "\n" + "Fixed version:     See vendor advisory";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

