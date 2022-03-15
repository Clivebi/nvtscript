if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900222" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)" );
	script_bugtraq_id( 29653 );
	script_cve_id( "CVE-2008-2364" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Denial of Service" );
	script_name( "IBM HTTP Server mod_proxy Interim Responses DoS Vulnerability" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80, 8880, 8008 );
	script_mandatory_keys( "IBM_HTTP_Server/banner" );
	script_xref( name: "URL", value: "http://secunia.com/Advisories/31904/" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/42987" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?rs=177&context=SSEQTJ&uid=swg21173021" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg27008517" );
	script_tag( name: "summary", value: "This host is running IBM HTTP Server, which is prone to Denial of
  Service Vulnerability." );
	script_tag( name: "insight", value: "Issue is due to an error in the ap_proxy_http_process_response()
  function in mod_proxy_http.c in the mod_proxy module when processing large number of interim responses
  to the client, which could consume all available memory resources." );
	script_tag( name: "affected", value: "IBM HTTP Server versions prior to 6.1.0.19." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Update to Fix Pack 19." );
	script_tag( name: "impact", value: "A remote/local user can cause denial of service." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
ibmWebSer = http_get_remote_headers( port: port );
if(ibmWebSer && egrep( pattern: "Server: IBM_HTTP_Server.*", string: ibmWebSer )){
	if(egrep( pattern: "IBM_HTTP_Server/([0-5]\\..*|6\\.[01])[^.0-9]", string: ibmWebSer )){
		security_message( port );
		exit( 0 );
	}
}

