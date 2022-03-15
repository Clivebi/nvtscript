if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103462" );
	script_bugtraq_id( 52566 );
	script_cve_id( "CVE-2012-1841", "CVE-2012-1842", "CVE-2012-1844" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Multiple Vendor Products Security Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52566" );
	script_xref( name: "URL", value: "http://www.quantum.com/ServiceandSupport/SoftwareandDocumentationDownloads/SI500/Index.aspx" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/913483" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-04-11 09:50:54 +0200 (Wed, 11 Apr 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Quantum Scalar i500, Dell ML6000, and IBM TS3310 are prone to following vulnerabilities:

  1. An information-disclosure vulnerability

  2. A cross-site scripting vulnerability

  3. A cross-site request-forgery vulnerability

  4. A security-bypass vulnerability" );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the
  affected site. This may let the attacker steal cookie-based
  authentication credentials and launch other attacks. The information-
  disclosure vulnerability can allow the attacker to obtain sensitive
  information that may aid in launching further attacks.

  Exploiting the cross-site request-forgery may allow a remote attacker
  to perform certain administrative actions and gain unauthorized access
  to the affected application. Other attacks are also possible.

  Attackers can exploit a password weakness issue to bypass security
  restrictions to obtain sensitive information or perform unauthorized
  actions, this may aid in launching further attacks." );
	script_tag( name: "solution", value: "Updates are available. Check the references." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
url = "/index.htm";
buf = http_get_cache( port: port, item: url );
if(egrep( string: buf, pattern: "(<title>QUANTUM - Scalar|<title>DELL - ML.* Login Screen)" )){
	files = traversal_files();
	for pattern in keys( files ) {
		file = files[pattern];
		url = "/logShow.htm?file=/" + file;
		if(http_vuln_check( port: port, url: url, pattern: pattern )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( data: report, port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

