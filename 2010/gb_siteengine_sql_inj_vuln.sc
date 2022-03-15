if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801682" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-12-31 07:04:16 +0100 (Fri, 31 Dec 2010)" );
	script_bugtraq_id( 45056 );
	script_cve_id( "CVE-2010-4357" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "SiteEngine 'module' SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42353" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15612" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_siteengine_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "siteengine/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL
  Injection attack and gain sensitive information." );
	script_tag( name: "affected", value: "SiteEngine Version 7.1." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  via the 'module' parameter in comments.php that allows attackers to manipulate
  SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running SiteEngine and is prone to SQL injection
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
seVer = get_version_from_kb( port: port, app: "SiteEngine" );
if(!seVer){
	exit( 0 );
}
if(version_is_equal( version: seVer, test_version: "7.1" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

