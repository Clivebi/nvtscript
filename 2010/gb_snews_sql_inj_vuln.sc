CPE = "cpe:/a:solucija:snews";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801243" );
	script_version( "2019-09-07T11:55:45+0000" );
	script_tag( name: "last_modification", value: "2019-09-07 11:55:45 +0000 (Sat, 07 Sep 2019)" );
	script_tag( name: "creation_date", value: "2010-08-04 08:26:41 +0200 (Wed, 04 Aug 2010)" );
	script_cve_id( "CVE-2010-2926" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "sNews 'category' parameter SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/60622" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14465/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_snews_detect.sc" );
	script_mandatory_keys( "snews/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL Injection
  attack and gain sensitive information." );
	script_tag( name: "affected", value: "sNews Version 1.7." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  via the 'category' parameter in 'index.php' that allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running sNews and is prone to a SQL injection
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "1.7" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

