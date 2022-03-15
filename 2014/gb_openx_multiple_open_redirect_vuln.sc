CPE = "cpe:/a:openx:openx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804877" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2014-2230" );
	script_bugtraq_id( 70603 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-11-05 11:59:46 +0530 (Wed, 05 Nov 2014)" );
	script_name( "OpenX Multiple Open Redirect Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with OpenX and
  is prone to multiple open redirect vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check
  whether it redirects to the malicious websites." );
	script_tag( name: "insight", value: "Multiple errors exist as the application
  does not validate the inputs passed via 'dest' parameter to adclick.php script
  and '_maxdest' parameter to ck.php script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to create a specially crafted URL, that if clicked, would redirect
  a victim from the intended legitimate web site to an arbitrary web site of the
  attacker's choosing." );
	script_tag( name: "affected", value: "OpenX version 2.8.10 and probably prior." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/97621" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/128718" );
	script_xref( name: "URL", value: "http://www.tetraph.com/blog/cves/cve-2014-2230-openx-open-redirect-vulnerability-2" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "OpenX_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "openx/installed" );
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
url = dir + "/www/delivery/ck.php?_maxdest=http://www.example.com";
sndReq = http_get( item: url, port: port );
rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
if(rcvRes && IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 302" ) && IsMatchRegexp( rcvRes, "Location.*http://www.example.com" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

