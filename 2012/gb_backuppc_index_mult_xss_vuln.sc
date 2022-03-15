if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802622" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 47628, 50406 );
	script_cve_id( "CVE-2011-3361", "CVE-2011-5081", "CVE-2011-4923" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-04-04 14:49:38 +0530 (Wed, 04 Apr 2012)" );
	script_name( "BackupPC 'index.cgi' Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44259" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44385" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46615" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1249-1" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/67170" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/71030" );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/multiple_xss_vulnerabilities_in_backuppc.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site." );
	script_tag( name: "affected", value: "BackupPC version 3.2.0 and prior." );
	script_tag( name: "insight", value: "Multiple flaws are due to improper validation of user-supplied
  input to 'num' and 'share' parameters in index.cgi, which allows attackers to
  execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site." );
	script_tag( name: "solution", value: "Upgrade to BackupPC version 3.2.1 or later." );
	script_tag( name: "summary", value: "This host is running BackupPC and is prone to multiple cross site
  scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/backuppc", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.cgi";
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<title>BackupPC" )){
		url += "?action=RestoreFile&host=localhost&num=1&share=" + "<script>alert(document.cookie)</script>";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>", extra_check: "<title>BackupPC" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

