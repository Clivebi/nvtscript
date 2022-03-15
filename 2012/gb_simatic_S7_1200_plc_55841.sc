CPE = "cpe:/a:siemens:simatic_s7_1200";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103584" );
	script_bugtraq_id( 55841 );
	script_version( "$Revision: 11855 $" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2012-3040" );
	script_name( "Siemens SIMATIC S7-1200 PLC 'web server' Component Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55841" );
	script_xref( name: "URL", value: "http://www.siemens.com/corporate-technology/pool/de/forschungsfelder/siemens_security_advisory_ssa-279823.pdf" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 09:34:51 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-10-10 12:27:02 +0200 (Wed, 10 Oct 2012)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_simatic_s7_version.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "simatic_s7/detected" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Siemens SIMATIC S7-1200 Programmable Logic Controller (PLC) is prone
 to a cross-site scripting vulnerability because it fails to properly
 sanitize user-supplied input.

 An attacker may leverage this issue to execute arbitrary script code
 in the browser of an unsuspecting user in the context of the affected
 site. This can allow the attacker to steal cookie-based authentication
 credentials and launch other attacks." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "3.0.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.0.2" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

