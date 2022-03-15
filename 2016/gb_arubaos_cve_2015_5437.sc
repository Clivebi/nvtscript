CPE = "cpe:/o:arubanetworks:arubaos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105657" );
	script_cve_id( "CVE-2015-5437" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_version( "$Revision: 12363 $" );
	script_name( "ArubaOS Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.arubanetworks.com/assets/alert/ARUBA-PSA-2015-011.txt" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The ArubaOS advisory covers three vulnerabilities :

  - Reflected Cross-Site Scripting

A reflected cross-site scripting vulnerability is present in the a monitoring page in the WebUI.  If an
administrator were tricked into clicking on a malicious URL while logged into an Aruba controller's
management interface, this vulnerability could potentially reveal a session cookie.

  - Cross-Site Request Forgery

Most configuration-related pages in the ArubaOS management UI are protected against cross-site request
forgery (CSRF) through the use of a unique, random token.  It was found that certain operations which
could reveal sensitive information, such as the controller configuration file, were not protected
against CSRF.  If an administrator were tricked into clicking on a malicious URL while logged into an
Aruba controller's management interface, this vulnerability could leak sensitive information to an
attacker.

  - Crafted frame causes AP-225 reboot

Sending a specific malformed wireless frame to an AP-225 may cause the AP to reboot. Aruba inadvertently
documented this in ArubaOS release notes before a security advisory could be issued. We regret the
error and have taken steps to prevent future accidental disclosures of availability threats." );
	script_tag( name: "solution", value: "The vulnerabilities have been addressed in the following versions:

  - ArubaOS 6.3.1.19

  - ArubaOS 6.4.2.13

  - ArubaOS 6.4.3.4

  - ArubaOS 6.4.4.0" );
	script_tag( name: "summary", value: "ArubaOS is prone to multiple vulnerabilities" );
	script_tag( name: "affected", value: "- ArubaOS 6.3 up to, but not including, 6.3.1.19

  - ArubaOS 6.4 up to, but not including, 6.4.2.13 and 6.4.3.4" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-05-06 16:08:57 +0200 (Fri, 06 May 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_arubaos_detect.sc" );
	script_mandatory_keys( "ArubaOS/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.3", test_version2: "6.3.1.18" )){
	fix = "6.3.1.19";
}
if(version_in_range( version: version, test_version: "6.4.2", test_version2: "6.4.2.12" )){
	fix = "6.4.2.13";
}
if(version_in_range( version: version, test_version: "6.4.3", test_version2: "6.4.3.3" )){
	fix = "6.4.3.4";
}
if(fix){
	model = get_kb_item( "ArubaOS/model" );
	report = "Installed Version: " + version + "\n" + "Fixed Version:     " + fix + "\n";
	if(model){
		report += "Model:             " + model + "\n";
	}
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

