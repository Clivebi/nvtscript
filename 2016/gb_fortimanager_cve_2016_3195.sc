CPE = "cpe:/h:fortinet:fortimanager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105865" );
	script_cve_id( "CVE-2016-3195", "CVE-2016-3194", "CVE-2016-3193" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2021-09-20T14:01:48+0000" );
	script_name( "Fortinet FortiManager Multiple XSS Vulnerabilities (FG-IR-16-015, FG-IR-16-016, FG-IR-16-017)" );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-16-015" );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-16-016" );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-16-017" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 5.0.12, 5.2.6, 5.4.0 or later." );
	script_tag( name: "summary", value: "FortiManager is prone to multiple cross-site scripting (XSS)
  vulnerabilities." );
	script_tag( name: "insight", value: "The following flaws exist:

  - An XSS vulnerability in FortiManager/FortiAnalyzer could allow privileged guest user accounts
  and restricted user accounts to inject malicious script to the application-side or client-side of
  the appliance web-application. This potentially enables XSS attacks.

  - A vulnerability in FortiManager/FortiAnalyzer address added page could allow malicious script
  being injected in the input field. This potentially enables XSS attacks.

  - A client side XSS vulnerability in FortiManager/FortiAnalyzer could allow malicious script being
  injected in the Web-UI. This potentially enables XSS attacks." );
	script_tag( name: "affected", value: "FortiManager version 5.0.0 through 5.0.11, 5.2.0 through 5.2.5
  and 5.4.0." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-09-20 14:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)" );
	script_tag( name: "creation_date", value: "2016-08-12 12:59:41 +0200 (Fri, 12 Aug 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "FortiOS Local Security Checks" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_fortimanager_version.sc" );
	script_mandatory_keys( "fortimanager/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.11" )){
	fix = "5.0.12";
}
if(version_in_range( version: version, test_version: "5.2.0", test_version2: "5.2.5" )){
	fix = "5.2.6";
}
if(version_in_range( version: version, test_version: "5.4", test_version2: "5.4.0" )){
	fix = "5.4.1";
}
if(fix){
	model = get_kb_item( "fortimanager/model" );
	if(!isnull( model )){
		report = "Model:             " + model + "\n";
	}
	report += "Installed Version: " + version + "\nFixed Version:     " + fix + "\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

