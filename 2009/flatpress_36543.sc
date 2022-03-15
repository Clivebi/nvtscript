CPE = "cpe:/a:flatpress:flatpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100295" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-10-06 18:45:43 +0200 (Tue, 06 Oct 2009)" );
	script_bugtraq_id( 36543 );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "FlatPress 'userid' Parameter Local File Include Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36543" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53589" );
	script_xref( name: "URL", value: "https://sourceforge.net/project/shownotes.php?group_id=157089&release_id=628765" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/506816" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "flatpress_detect.sc" );
	script_mandatory_keys( "flatpress/installed" );
	script_tag( name: "solution", value: "The vendor has released an update. Please see the references for details." );
	script_tag( name: "summary", value: "FlatPress is prone to a local file-include vulnerability because it fails to
  properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to obtain potentially sensitive
  information and execute arbitrary local scripts in the context of the webserver process. This may allow the
  attacker to compromise the application and the underlying computer, other attacks are also possible." );
	script_tag( name: "affected", value: "FlatPress 0.804 through 0.812.1 are vulnerable." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "0.804", test_version2: "0.812.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

