CPE = "cpe:/a:oracle:glassfish_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902456" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)" );
	script_cve_id( "CVE-2011-2260" );
	script_bugtraq_id( 48797 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle GlassFish Server Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17551/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/518923" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103167/SOS-11-009.txt" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "GlassFish_detect.sc" );
	script_mandatory_keys( "GlassFish/installed" );
	script_require_ports( "Services/www", 8080 );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary HTML and
script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "Oracle GlassFish Server version 2.1.1" );
	script_tag( name: "insight", value: "The flaw is due to error in the handling of log viewer, which fails to
securely output encode logged values. An unauthenticated attacker can trigger the application to log a malicious
string by entering the values into the username field." );
	script_tag( name: "solution", value: "Apply the security updates." );
	script_tag( name: "summary", value: "The host is running GlassFish Server and is prone to cross-site scripting
vulnerability." );
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
if(version_is_equal( version: version, test_version: "2.1.1" )){
	report = report_fixed_ver( installed_version: version, vulnerable_range: "Equal to 2.1.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

