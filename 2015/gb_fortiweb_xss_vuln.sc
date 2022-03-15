CPE = "cpe:/a:fortinet:fortiweb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805645" );
	script_version( "2021-07-12T08:06:48+0000" );
	script_cve_id( "CVE-2014-8619" );
	script_bugtraq_id( 74679 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-12 08:06:48 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2015-06-08 11:54:11 +0530 (Mon, 08 Jun 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fortinet FortiWeb Multiple Reflected XSS Vulnerabilities (FG-IR-15-005)" );
	script_tag( name: "summary", value: "Fortinet FortiWeb is prone to multiple reflected cross-site
  scripting (XSS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists because the autolearn configuration page does
  not validate input before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow a context-dependent attacker
  to create a specially crafted request that would execute arbitrary script code in a user's browser
  session within the trust relationship between their browser and the server." );
	script_tag( name: "affected", value: "Fortinet FortiWeb version 5.1.2 through 5.3.4." );
	script_tag( name: "solution", value: "Update to version 5.3.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-15-005" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "FortiOS Local Security Checks" );
	script_dependencies( "gb_fortiweb_version.sc" );
	script_mandatory_keys( "fortiweb/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "5.1.2", test_version2: "5.3.4" )){
	report = "Installed version: " + vers + "\n" + "Fixed version:     " + "5.3.5" + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

