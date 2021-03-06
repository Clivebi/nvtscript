CPE = "cpe:/a:cmsmadesimple:cms_made_simple";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100632" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-05-10 13:21:57 +0200 (Mon, 10 May 2010)" );
	script_bugtraq_id( 39997 );
	script_cve_id( "CVE-2010-1482" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "CMS Made Simple 'admin/editprefs.php' Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/39997" );
	script_xref( name: "URL", value: "http://blog.cmsmadesimple.org/2010/05/01/announcing-cms-made-simple-1-7-1-escade/" );
	script_xref( name: "URL", value: "http://www.cmsmadesimple.org/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/511178" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "cms_made_simple_detect.sc" );
	script_mandatory_keys( "cmsmadesimple/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "CMS Made Simple is prone to a cross-site scripting vulnerability because the
application fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may help the attacker steal cookie-based authentication credentials and launch
other attacks.

Versions prior to CMS Made Simple 1.7.1 are vulnerable." );
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
if(version_is_less( version: vers, test_version: "1.7.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.7.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

