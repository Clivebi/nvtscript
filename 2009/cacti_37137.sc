CPE = "cpe:/a:cacti:cacti";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100365" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-12-01 12:01:39 +0100 (Tue, 01 Dec 2009)" );
	script_bugtraq_id( 37137 );
	script_cve_id( "CVE-2009-4112" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cacti 'Linux - Get Memory Usage' Remote Command Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37137" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2009-11/0292.html" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "cacti_detect.sc" );
	script_mandatory_keys( "cacti/installed" );
	script_tag( name: "summary", value: "Cacti is prone to a remote command-execution vulnerability because the
  software fails to adequately sanitize user-supplied input." );
	script_tag( name: "impact", value: "Successful attacks can compromise the affected software and possibly the host." );
	script_tag( name: "solution", value: "Update to version 0.8.7e or later." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "0.8.7e" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.8.7e" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

