if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100890" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-11-03 12:47:25 +0100 (Wed, 03 Nov 2010)" );
	script_bugtraq_id( 43454 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-3490" );
	script_name( "FreePBX System Recordings Menu Arbitrary File Upload Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/43454" );
	script_xref( name: "URL", value: "http://freepbx.org" );
	script_xref( name: "URL", value: "http://www.freepbx.org/trac/ticket/4553" );
	script_xref( name: "URL", value: "https://www.trustwave.com/spiderlabs/advisories/TWSL2010-005.txt" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/513947" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_freepbx_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "freepbx/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available, please see the references for more information." );
	script_tag( name: "summary", value: "FreePBX is prone to an arbitrary file-upload vulnerability because it
fails to properly sanitize user-supplied input.

An attacker can leverage this issue to upload arbitrary files to the
affected computer, this can result in arbitrary code execution within
the context of the webserver.

FreePBX 2.8.0 is vulnerable, other versions may also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(vers = get_version_from_kb( port: port, app: "freepbx" )){
	if(version_is_less_equal( version: vers, test_version: "2.8.0" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "Less than or equal to 2.8.0" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

