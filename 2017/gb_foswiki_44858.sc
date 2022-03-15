CPE = "cpe:/a:foswiki:foswiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108059" );
	script_version( "$Revision: 14117 $" );
	script_bugtraq_id( 44858 );
	script_tag( name: "last_modification", value: "$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2017-01-27 13:41:11 +0100 (Fri, 27 Jan 2017)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-4215" );
	script_name( "Foswiki Topic Settings Remote Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_foswiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Foswiki/installed" );
	script_xref( name: "URL", value: "http://foswiki.org/Support/SecurityAlert-CVE-2010-4215" );
	script_tag( name: "impact", value: "Remote attackers with the ability to edit topic settings can exploit this
  issue to gain administrative privileges. This may aid in further attacks." );
	script_tag( name: "affected", value: "Foswiki 1.1.0 and 1.1.1 are vulnerable." );
	script_tag( name: "solution", value: "Upgrade to version 1.1.2 or later." );
	script_tag( name: "summary", value: "Foswiki is prone to a remote privilege-escalation vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_in_range( version: vers, test_version: "1.1.0", test_version2: "1.1.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.1.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

