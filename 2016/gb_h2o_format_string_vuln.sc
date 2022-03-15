CPE = "cpe:/a:h2o_project:h2o";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106247" );
	script_version( "$Revision: 12096 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-09-15 15:47:03 +0700 (Thu, 15 Sep 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2016-4864" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "H2O HTTP Server Format String Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_h2o_http_server_detect.sc" );
	script_mandatory_keys( "h2o/installed" );
	script_tag( name: "summary", value: "H2O HTTP Server is prone to a format string vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A format string vulnerability exists in H2O, that can be used by remote
attackers to mount Denial-of-Service attacks.

Users using one of the handlers (fastcgi, mruby, proxy, redirect, reproxy) of H2O may be affected by the issue." );
	script_tag( name: "impact", value: "An unauthenticated remote attacker may cause a denial of service condition." );
	script_tag( name: "affected", value: "H2O version 2.0.3, 2.1.0-beta2 and prior." );
	script_tag( name: "solution", value: "Update to version 2.0.4, 2.1.0-beta3 or later." );
	script_xref( name: "URL", value: "https://github.com/h2o/h2o/issues/1077" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
check_vers = ereg_replace( string: version, pattern: "-", replace: "." );
if(version_is_less( version: check_vers, test_version: "2.0.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: check_vers, test_version: "2.1.0", test_version2: "2.1.0.beta2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1.0-beta3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

