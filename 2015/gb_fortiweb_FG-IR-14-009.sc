CPE = "cpe:/a:fortinet:fortiweb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105205" );
	script_cve_id( "CVE-2014-1955", "CVE-2014-1956", "CVE-2014-1957" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_version( "2021-07-12T08:06:48+0000" );
	script_name( "Fortinet FortiWeb Multiple Vulnerabilities (FG-IR-13-009)" );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-13-009" );
	script_tag( name: "impact", value: "A remote unauthenticated attacker may be able to execute arbitrary JavaScript in the context of the administrator's browser
  session. In addition, authenticated users may be able to escalate their privileges." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to FortiWeb 5.0.3 or later." );
	script_tag( name: "summary", value: "FortiWeb 5.0.2 and lower are vulnerable to cross-site scripting (CVE-2014-1955), HTTP header injection (CVE-2014-1956) and privilege
  escalation (CVE-2014-1957) issues." );
	script_tag( name: "affected", value: "FortiWeb 4.4.7 and lower. FortiWeb 5.0.2 and earlier." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-07-12 08:06:48 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2015-02-11 12:17:13 +0100 (Wed, 11 Feb 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "FortiOS Local Security Checks" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_fortiweb_version.sc" );
	script_mandatory_keys( "fortiweb/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
version = get_app_version( cpe: CPE );
if(!version){
	version = get_kb_item( "fortiweb/version" );
}
if(!version){
	exit( 0 );
}
fix = "5.0.3";
if(version_is_less( version: version, test_version: fix )){
	model = get_kb_item( "fortiweb/model" );
	if(!isnull( model )){
		report = "Model:             " + model + "\n";
	}
	report += "Installed Version: " + version + "\nFixed Version:     " + fix + "\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

