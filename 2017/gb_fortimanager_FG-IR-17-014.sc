CPE = "cpe:/h:fortinet:fortimanager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140263" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-01 16:24:31 +0700 (Tue, 01 Aug 2017)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-08 01:29:00 +0000 (Sat, 08 Jul 2017)" );
	script_cve_id( "CVE-2017-3126" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Fortinet FortiManager Open Redirect Vulnerability (FG-IR-17-014)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "FortiOS Local Security Checks" );
	script_dependencies( "gb_fortimanager_version.sc" );
	script_mandatory_keys( "fortimanager/version" );
	script_tag( name: "summary", value: "The FortiManager WebUI accept a user-controlled input that specifies a link
to an external site, and uses that link in a redirect." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Open redirect" );
	script_tag( name: "affected", value: "FortiManager versions 5.4.0 to 5.4.2." );
	script_tag( name: "solution", value: "Update to version 5.4.3 or later." );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-17-014" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.4.0", test_version2: "5.4.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.4.3" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

