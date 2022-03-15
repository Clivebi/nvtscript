if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902508" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)" );
	script_cve_id( "CVE-2011-1685" );
	script_bugtraq_id( 47383 );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_name( "RT (Request Tracker) Cross Site Request Forgery Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44189" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/66791" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=696795" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "rt_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "RequestTracker/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code with
  the permissions of the web server." );
	script_tag( name: "affected", value: "RT (Request Tracker) versions 3.8.0 through 3.8.9 and 4.0.0rc through 4.0.0rc7." );
	script_tag( name: "insight", value: "The flaw is caused by an error in the external custom field feature, which
  allows remote authenticated users to execute arbitrary code via unspecified vectors." );
	script_tag( name: "solution", value: "Upgrade to RT (Request Tracker) version 3.8.10 or 4.0.0rc8." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Request Tracker and is prone to
  cross site request forgery vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(vers = get_version_from_kb( port: port, app: "rt_tracker" )){
	if(version_in_range( version: vers, test_version: "3.8.0", test_version2: "3.8.9" ) || version_in_range( version: vers, test_version: "4.0.0.rc1", test_version2: "4.0.0.rc7" )){
		security_message( port: port );
	}
}

