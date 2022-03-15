CPE = "cpe:/a:oracle:glassfish_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802927" );
	script_version( "$Revision: 11878 $" );
	script_bugtraq_id( 50846 );
	script_cve_id( "CVE-2011-4358" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 14:40:08 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-07 13:44:27 +0530 (Tue, 07 Aug 2012)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle GlassFish Server Expression Evaluation Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49956/" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46959/" );
	script_xref( name: "URL", value: "http://java.net/jira/browse/JAVASERVERFACES-2247" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujul2012-392727.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujul2012verbose-392736.html#Oracle%20Sun%20Products%20Suit" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "GlassFish_detect.sc" );
	script_mandatory_keys( "GlassFish/installed" );
	script_require_ports( "Services/www", 8080 );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
script code in the browser of an unsuspecting user in the context of an affected application." );
	script_tag( name: "affected", value: "Oracle GlassFish Server version 3.0.1 and 3.1.1" );
	script_tag( name: "insight", value: "An unspecified error in the application, allows remote attackers to bypass
certain security restrictions." );
	script_tag( name: "summary", value: "This host is running Oracle GlassFish Server and is prone to a security
bypass vulnerability." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
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
if(version_is_equal( version: version, test_version: "3.0.1" ) || version_is_equal( version: version, test_version: "3.1.1" )){
	security_message( port );
	exit( 0 );
}
exit( 99 );

