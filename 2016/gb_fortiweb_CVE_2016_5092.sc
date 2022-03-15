CPE = "cpe:/a:fortinet:fortiweb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105796" );
	script_cve_id( "CVE-2016-5092" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_version( "2021-07-13T08:19:02+0000" );
	script_name( "Fortinet FortiWeb Path Traversal Vulnerability (FG-IR-16-009)" );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-16-009" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 5.5.3 or later." );
	script_tag( name: "summary", value: "Fortinet FortiWeb is prone a path traversal vulnerability." );
	script_tag( name: "insight", value: "A path traversal vulnerability allows an administrator account
  with read and write privileges to read arbitrary files using the autolearn feature." );
	script_tag( name: "affected", value: "FortiWeb 4.4.6 through 5.5.2 with the autolearn feature
  configured." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-07-13 08:19:02 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "creation_date", value: "2016-07-05 19:08:43 +0200 (Tue, 05 Jul 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "FortiOS Local Security Checks" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_fortiweb_version.sc" );
	script_mandatory_keys( "fortiweb/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
fix = "5.5.3";
if(version_in_range( version: version, test_version: "4.4.6", test_version2: "5.5.2" )){
	model = get_kb_item( "fortiweb/model" );
	if(!isnull( model )){
		report = "Model:             " + model + "\n";
	}
	report += "Installed Version: " + version + "\nFixed Version:     " + fix + "\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

