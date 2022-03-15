CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900150" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-10-14 16:57:31 +0200 (Tue, 14 Oct 2008)" );
	script_bugtraq_id( 31663 );
	script_cve_id( "CVE-2008-4411" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_name( "HP System Management Homepage Unspecified XSS Vulnerability" );
	script_dependencies( "secpod_hp_smh_detect.sc" );
	script_mandatory_keys( "HP/SMH/installed" );
	script_require_ports( "Services/www", 2301, 2381 );
	script_tag( name: "affected", value: "HP System Management Homepage versions prior to 2.1.15.210." );
	script_tag( name: "summary", value: "The host is running HP System Management Homepage, which is prone
  to unspecified XSS Vulnerability.

  Certain input parameters are not properly sanitized before returned to the user." );
	script_tag( name: "solution", value: "Update to version 2.1.15.210 or later." );
	script_tag( name: "impact", value: "An attacker can execute arbitrary script code in the user's browser session." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32199/" );
	script_xref( name: "URL", value: "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01570589" );
	script_xref( name: "URL", value: "http://h20000.www2.hp.com/bizsupport/TechSupport/SoftwareDescription.jsp?swItem=MTX-e85a4029b2dd42959f1f82dda7" );
	script_xref( name: "URL", value: "http://h20000.www2.hp.com/bizsupport/TechSupport/SoftwareDescription.jsp?swItem=MTX-5c90113499bb41faacdcad9485" );
	script_xref( name: "URL", value: "http://h20000.www2.hp.com/bizsupport/TechSupport/SoftwareDescription.jsp?swItem=MTX-84b4161b7cd3455fb34ac57586" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
if(version_is_less( version: version, test_version: "2.1.15.210" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1.15.210" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

