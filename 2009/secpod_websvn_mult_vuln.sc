if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900441" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-5918", "CVE-2008-5919", "CVE-2008-5920", "CVE-2009-0240" );
	script_bugtraq_id( 31891 );
	script_name( "WebSVN Script Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32338" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/6822" );
	script_xref( name: "URL", value: "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=512191" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_websvn_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "WebSVN/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the web application and execute cross site scripting attacks and
  can gain sensitive information or can cause directory traversal attacks." );
	script_tag( name: "affected", value: "WebSVN version prior to 2.1.0." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to version 2.1.0." );
	script_tag( name: "summary", value: "This host is running WebSVN and is prone to Multiple
  Vulnerabilities." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - input passed in the URL to index.php is not properly sanitised before
  being returned to the user.

  - input passed to the rev parameter in rss.php is not properly sanitised
  before being used, when magic_quotes_gpc is disable.

  - restricted access to the repositories is not properly enforced." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
websvnPort = http_get_port( default: 80 );
svnVer = get_kb_item( "www/" + websvnPort + "/WebSVN" );
if(!svnVer){
	exit( 0 );
}
if(version_is_less( version: svnVer, test_version: "2.1.0" )){
	report = report_fixed_ver( installed_version: svnVer, fixed_version: "2.1.0" );
	security_message( port: websvnPort, data: report );
	exit( 0 );
}
exit( 99 );

