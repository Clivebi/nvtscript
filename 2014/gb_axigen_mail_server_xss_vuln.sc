CPE = "cpe:/a:gecad_technologies:axigen_mail_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804669" );
	script_version( "$Revision: 11974 $" );
	script_cve_id( "CVE-2012-2592" );
	script_bugtraq_id( 54899 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2014-07-07 14:34:53 +0530 (Mon, 07 Jul 2014)" );
	script_name( "AXIGEN Mail Server Email Message Cross-site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Axigen Mail Server and is prone to cross-site
scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to application which does not validate input passed via an
email message before returning it to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary script code
in a user's browser within the trust relationship between their browser and the server." );
	script_tag( name: "affected", value: "Axigen Mail Server version 8.0.1" );
	script_tag( name: "solution", value: "Upgrade to Axigen Mail Server version 8.1.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50062" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/77515" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "axigen_web_detect.sc" );
	script_mandatory_keys( "axigen/installed" );
	script_xref( name: "URL", value: "http://www.axigen.com" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!axigenVer = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: axigenVer, test_version: "8.0.1" )){
	report = report_fixed_ver( installed_version: axigenVer, fixed_version: "8.1.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

