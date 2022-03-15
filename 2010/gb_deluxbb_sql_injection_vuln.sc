CPE = "cpe:/a:deluxebb:deluxebb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801334" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-1859" );
	script_bugtraq_id( 39962 );
	script_name( "DeluxeBB 'newpost.php' SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "deluxeBB_detect.sc" );
	script_mandatory_keys( "deluxebb/installed" );
	script_xref( name: "URL", value: "http://www.security-database.com/detail.php?alert=CVE-2010-1859" );
	script_xref( name: "URL", value: "http://php-security.org/2010/05/06/mops-2010-011-deluxebb-newthread-sql-injection-vulnerability/index.html" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute
  arbitrary SQL commands via the membercookie cookie when adding a new thread." );
	script_tag( name: "affected", value: "DeluxeBB version 1.3 and prior." );
	script_tag( name: "insight", value: "The flaw is due to error in 'newpost.php', which is not properly
  sanitizing user supplied input data." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running DeluxeBB and is prone to SQL injection
  vulnerability." );
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

