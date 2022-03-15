if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801997" );
	script_version( "2020-04-01T10:41:43+0000" );
	script_tag( name: "last_modification", value: "2020-04-01 10:41:43 +0000 (Wed, 01 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-11-03 12:22:48 +0100 (Thu, 03 Nov 2011)" );
	script_cve_id( "CVE-2011-3559" );
	script_bugtraq_id( 50204 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Oracle GlassFish/System Application Server Web Container DOS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "GlassFish_detect.sc", "secpod_sun_java_app_serv_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "glassfish_or_sun_java_appserver/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46524" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46523" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/70816" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1026222" );
	script_tag( name: "impact", value: "Successful exploitation could allow malicious attackers to cause a denial of
  service." );
	script_tag( name: "affected", value: "Oracle GlassFish version 2.1.1, 3.0.1 and 3.1.1 and Oracle Java System
  Application Server version 8.1 and 8.2" );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error within the Web Container component,
  which allows remote users to cause denial of service conditions." );
	script_tag( name: "summary", value: "The host is running GlassFish/System Application Server and is prone to
  denial of service vulnerability." );
	script_tag( name: "solution", value: "Apply the security updates." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:oracle:glassfish_server",
	 "cpe:/a:sun:java_system_application_server" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
CPE = infos["cpe"];
port = infos["port"];
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( CPE == "cpe:/a:oracle:glassfish_server" ){
	if(version_in_range( version: vers, test_version: "3.0", test_version2: "3.1.1" ) || version_in_range( version: vers, test_version: "2.1", test_version2: "2.1.1" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: path );
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
else {
	if(CPE == "cpe:/a:sun:java_system_application_server"){
		vers = ereg_replace( pattern: "_", replace: ".", string: vers );
		if(version_is_equal( version: vers, test_version: "8.0.01" ) || version_is_equal( version: vers, test_version: "8.0.02" )){
			report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: path );
			security_message( port: port, data: report );
			exit( 0 );
		}
		exit( 99 );
	}
}
exit( 0 );

