CPE = "cpe:/h:fortinet:fortimanager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105816" );
	script_cve_id( "CVE-2016-3196" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_version( "2021-07-12T08:06:48+0000" );
	script_name( "Fortinet FortiManager Persistent XSS Vulnerability (FG-IR-16-014)" );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-16-014" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to FortiManager 5.2.6, 5.4.0 or later." );
	script_tag( name: "summary", value: "When a low privileged user uploads images in the report section,
  the filenames are not properly sanitized. This potentially enables stored XSS attacks." );
	script_tag( name: "affected", value: "FortiManager version 5.0.0 through 5.0.11 and 5.2.0 through 5.2.5." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-07-12 08:06:48 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2016-07-19 10:34:06 +0200 (Tue, 19 Jul 2016)" );
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
fix = "5.2.6/5.4.0";
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.11" ) || version_in_range( version: version, test_version: "5.2.0", test_version2: "5.2.5" )){
	model = get_kb_item( "fortimanager/model" );
	if(!isnull( model )){
		report = "Model:             " + model + "\n";
	}
	report += "Installed Version: " + version + "\nFixed Version:     " + fix + "\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

