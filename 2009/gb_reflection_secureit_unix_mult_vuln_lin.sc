CPE = "cpe:/a:attachmate:reflection_for_secure_it";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800228" );
	script_version( "$Revision: 13794 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-20 15:59:32 +0100 (Wed, 20 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-6021" );
	script_bugtraq_id( 30723 );
	script_name( "Reflection for Secure IT Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_reflection_secureit_unix_detect_lin.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "attachmate/reflection_for_secure_it/detected" );
	script_xref( name: "URL", value: "http://support.attachmate.com/techdocs/2288.html" );
	script_xref( name: "URL", value: "http://support.attachmate.com/techdocs/2374.html#Security_Updates_in_7.0_SP1" );
	script_tag( name: "affected", value: "Reflections for Secure IT version prior to 7.0 SP1." );
	script_tag( name: "insight", value: "Unknown Vector." );
	script_tag( name: "solution", value: "Apply the security update SP1." );
	script_tag( name: "summary", value: "This host is installed with Reflections for Secure IT and is prone
  to multiple vulnerabilities." );
	script_tag( name: "impact", value: "Attacker can get admin privileges." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "ssh" )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "7.0.1.575" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.0.1.575" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

