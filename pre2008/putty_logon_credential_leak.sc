if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14263" );
	script_version( "2021-05-26T15:17:57+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 15:17:57 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 6724 );
	script_cve_id( "CVE-2003-0048" );
	script_xref( name: "OSVDB", value: "7687" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PuTTY SSH2 Authentication Password Persistence Weakness" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Windows" );
	script_dependencies( "gb_putty_portable_detect.sc" );
	script_mandatory_keys( "putty/detected" );
	script_tag( name: "summary", value: "PuTTY does not safely handle password information." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "As a result, a local user may be able to recover authentication
  passwords." );
	script_tag( name: "affected", value: "PuTTY version 0.54a and earlier." );
	script_tag( name: "solution", value: "Update to version 0.70 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
CPE = "cpe:/a:putty:putty";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "0.70" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.70", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

