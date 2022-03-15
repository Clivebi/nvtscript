CPE = "cpe:/a:deluxebb:deluxebb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100862" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-10-21 13:52:26 +0200 (Thu, 21 Oct 2010)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-4151" );
	script_bugtraq_id( 44259 );
	script_name( "DeluxeBB 'xthedateformat' Parameter SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "deluxeBB_detect.sc" );
	script_mandatory_keys( "deluxebb/installed" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44259" );
	script_xref( name: "URL", value: "http://www.deluxebb.com/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/514374" );
	script_tag( name: "summary", value: "DeluxeBB is prone to an SQL-injection vulnerability because it fails to
  sufficiently sanitize user-supplied data before using it in an SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "DeluxeBB 1.3 and prior are vulnerable." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_is_less_equal( version: version, test_version: "1.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "WillNotFix" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

