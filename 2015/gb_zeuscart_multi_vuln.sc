CPE = "cpe:/a:zeuscart:zeuscart";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105956" );
	script_version( "$Revision: 11452 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-02 09:33:03 +0700 (Mon, 02 Mar 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_cve_id( "CVE-2015-2182", "CVE-2015-2183", "CVE-2015-2184" );
	script_name( "Zeuscart Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zeuscart_detect.sc" );
	script_mandatory_keys( "zeuscart/installed" );
	script_tag( name: "summary", value: "Zeuscart is vulnerable to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check
  the response" );
	script_tag( name: "insight", value: "- XSS vulnerabilities in the parameters
  'search', 'schltr' and 'brand' which are used in index.php.

  - SQL Injections in the 'id' parameter in 'admin/?do=disporders&action=detail&id=',
  in the 'cid' parameter in 'admin/?do=editcurrency&cid=' and in the 'id' parameter
  in 'admin/?do=subadminmgt&action=edit&id='.

  - It is possible to get the PHP installation settings which are displayed through
  phpinfo() which is accessible as well to non-authenticated users." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database, execute
  arbitrary HTML and script code in a users  browser session in the context of an
  affected site or get information about system settings which might lead to
  further attacks." );
	script_tag( name: "affected", value: "Zeuscart 4.0 and below" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://github.com/ZeusCart/zeuscart/issues/28" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Feb/89" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/admin/?do=getphpinfo";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: ">phpinfo\\(\\)<", extra_check: make_list( ">System",
	 ">Configuration File" ) )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

