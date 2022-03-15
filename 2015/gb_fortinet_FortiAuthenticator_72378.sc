CPE = "cpe:/a:fortinet:fortiauthenticator";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105228" );
	script_bugtraq_id( 72378 );
	script_cve_id( "CVE-2015-1456", "CVE-2015-1455", "CVE-2015-1457", "CVE-2015-1459", "CVE-2015-1458" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_name( "Fortinet FortiAuthenticator Appliance Multiple Security Vulnerabilities (FG-IR-15-003)" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/72378" );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-15-003" );
	script_tag( name: "affected", value: "FortiAuthenticator lower than 3.2.1" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to FortiAuthenticator 3.2.1 or later." );
	script_tag( name: "summary", value: "Fortinet FortiAuthenticator Appliance is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following flaws exist:

1. A cross-site scripting vulnerability

2. A command-execution vulnerability

3. Multiple information-disclosure vulnerabilities" );
	script_tag( name: "impact", value: "An attacker can exploit these issues to execute arbitrary script code
in the context of the vulnerable site, potentially allowing the attacker to steal cookie-based authentication
credentials, execute arbitrary commands and gain access to potentially sensitive information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-03-02 10:40:16 +0100 (Mon, 02 Mar 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "FortiOS Local Security Checks" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_forti_authenticator_version.sc" );
	script_mandatory_keys( "fortiauthenticator/version" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
vers = get_app_version( cpe: CPE );
if(!vers){
	vers = get_kb_item( "fortiauthenticator/version" );
}
if(!vers){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "3.2.1" )){
	report = "Installed Version: " + vers + "\nFixed Version:     3.2.1\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

