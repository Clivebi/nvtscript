CPE = "cpe:/a:oracle:glassfish_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902286" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)" );
	script_cve_id( "CVE-2010-4438" );
	script_bugtraq_id( 45890 );
	script_tag( name: "cvss_base", value: "5.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:S/C:P/I:P/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle Java GlassFish Server Privilege Escalation Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42988" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/64813" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0155" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujan2011-194091.html" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "GlassFish_detect.sc" );
	script_mandatory_keys( "GlassFish/installed" );
	script_require_ports( "Services/www", 8080 );
	script_tag( name: "impact", value: "Successful exploitation could allow local attackers to affect confidentiality
and integrity via unknown vectors." );
	script_tag( name: "affected", value: "Oracle GlassFish version 2.1, 2.1.1 and 3.0.1" );
	script_tag( name: "insight", value: "The issue is caused by an unspecified error related to the Java Message
Service, which could allow local attackers to disclose or manipulate certain information, or create a denial of
service condition." );
	script_tag( name: "summary", value: "The host is running GlassFish Server and is prone to privilege escalation
vulnerability." );
	script_tag( name: "solution", value: "Apply the security updates." );
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
if(version_is_equal( version: version, test_version: "3.0.1" ) || version_in_range( version: version, test_version: "2.1", test_version2: "2.1.1" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

