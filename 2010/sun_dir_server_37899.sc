if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100510" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-02-26 12:01:21 +0100 (Fri, 26 Feb 2010)" );
	script_bugtraq_id( 37899 );
	script_cve_id( "CVE-2010-0708" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Sun Java System Directory Server LDAP Search Request Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "sun_dir_server_detect.sc" );
	script_require_ports( "Services/ldap", 389, 636 );
	script_mandatory_keys( "SunJavaDirServer/installed", "ldap/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37899" );
	script_xref( name: "URL", value: "http://www.sun.com/software/products/directory_srvr/home_directory.xml" );
	script_xref( name: "URL", value: "http://sunsolve.sun.com/search/document.do?assetkey=1-66-275711-1" );
	script_tag( name: "summary", value: "Sun Java System Directory Server is prone to a denial-of-service
  vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to crash the effected application,
  denying service to legitimate users." );
	script_tag( name: "affected", value: "- Sun Directory Server Enterprise Edition 7.0

  - Sun Java System Directory Server Enterprise Edition 6.3.1

  - Sun Java System Directory Server Enterprise Edition 6.3

  - Sun Java System Directory Server Enterprise Edition 6.2

  - Sun Java System Directory Server Enterprise Edition 6.1

  - Sun Java System Directory Server Enterprise Edition 6.0

  - Sun Java System Directory Server 5.2" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("ldap.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ldap_get_port( default: 389 );
if(!version = get_kb_item( "ldap/" + port + "/SunJavaDirServer" )){
	exit( 0 );
}
if(!isnull( version )){
	if(version_is_equal( version: version, test_version: "7.0" ) || version_in_range( version: version, test_version: "6", test_version2: "6.3.1" ) || version_is_equal( version: version, test_version: "5.2" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "See references" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

