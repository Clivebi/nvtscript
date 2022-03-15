if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103877" );
	script_bugtraq_id( 64719 );
	script_cve_id( "CVE-2013-7174" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_name( "QNAP QTS 'f' Parameter Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/64719" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-01-09 18:58:01 +0100 (Thu, 09 Jan 2014)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_require_ports( "Services/www", 80, 8080 );
	script_mandatory_keys( "qnap/qts" );
	script_tag( name: "impact", value: "A remote attacker could exploit the vulnerability using directory-
traversal characters ('../') to access arbitrary files that contain
sensitive information. Information harvested may aid in launching
further attacks." );
	script_tag( name: "vuldetect", value: "Check the firmware version." );
	script_tag( name: "insight", value: "QNAP QTS is a Network-Attached Storage (NAS) system
accessible via a web interface. QNAP QTS 4.0.3 and possibly earlier
versions contain a path traversal vulnerability via the cgi-bin/jc.cgi
CGI script. The script accepts an 'f' parameter which takes an
unrestricted file path as input." );
	script_tag( name: "solution", value: "Update to 4.1.0" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "QNAP QTS is prone to a directory-traversal vulnerability because it
fails to properly sanitize user-supplied input." );
	script_tag( name: "affected", value: "QNAP QTS 4.0.3 is vulnerable. Other versions may also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!get_kb_item( "qnap/qts" )){
	exit( 0 );
}
if(!version = get_kb_item( "qnap/version" )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "4.1.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.1.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

