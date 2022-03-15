CPE = "cpe:/h:fortinet:fortianalyzer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105200" );
	script_bugtraq_id( 70887 );
	script_cve_id( "CVE-2014-2334", "CVE-2014-2335", "CVE-2014-2336" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2021-07-12T08:06:48+0000" );
	script_name( "Fortinet FortiAnalyzer Multiple XSS Vulnerabilities (FG-IR-14-033)" );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-14-033" );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This can allow
  the attacker to steal cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 5.0.7 or later." );
	script_tag( name: "summary", value: "FortiAnalyzer is prone to multiple cross-site-scripting (XSS)
  vulnerabilities because it fails to properly sanitize user-supplied input." );
	script_tag( name: "affected", value: "Versions prior to 5.0.7 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-07-12 08:06:48 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2015-02-11 11:16:13 +0100 (Wed, 11 Feb 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "FortiOS Local Security Checks" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_fortianalyzer_version.sc" );
	script_mandatory_keys( "fortianalyzer/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
version = get_app_version( cpe: CPE );
if(!version){
	version = get_kb_item( "fortianalyzer/version" );
}
if(!version){
	exit( 0 );
}
fix = "5.0.7";
if(version_is_less( version: version, test_version: fix )){
	model = get_kb_item( "fortianalyzer/model" );
	if(!isnull( model )){
		report = "Model:             " + model + "\n";
	}
	report += "Installed Version: " + version + "\nFixed Version:     " + fix + "\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

