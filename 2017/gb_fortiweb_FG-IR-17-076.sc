CPE = "cpe:/a:fortinet:fortiweb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140265" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-01 16:47:59 +0700 (Tue, 01 Aug 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-02 12:39:00 +0000 (Fri, 02 Jun 2017)" );
	script_cve_id( "CVE-2017-3129" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Fortinet FortiWeb XSS Vulnerability (FG-IR-17-076)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "FortiOS Local Security Checks" );
	script_dependencies( "gb_fortiweb_version.sc" );
	script_mandatory_keys( "fortiweb/version" );
	script_tag( name: "summary", value: "The Site Publisher functionality of FortiWeb has been found vulnerable to a
Cross-Site Scripting vulnerability via an improperly sanitized parameter in a POST request." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Execute unauthorized code or commands." );
	script_tag( name: "affected", value: "FortiWeb version 5.7.1 and prior." );
	script_tag( name: "solution", value: "Update to version 5.8.0 or later." );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-17-076" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "5.8.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.8.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

