CPE = "cpe:/a:hp:sitescope";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801976" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)" );
	script_cve_id( "CVE-2011-2400", "CVE-2011-2401" );
	script_bugtraq_id( 48916, 48913 );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:P/A:P" );
	script_name( "HP SiteScope Cross-Site Scripting and Session Fixation Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45440" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1025856" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/68867" );
	script_xref( name: "URL", value: "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02940969" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "SiteScope/banner" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation could allow execution of scripts or actions
written by an attacker. In addition, an attacker may conduct session fixation attacks to hijack the target
user's session." );
	script_tag( name: "affected", value: "HP SiteScope version 9.x, 10.x, and 11.x" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Certain unspecified input is not properly sanitised before being returned to the user. This can be exploited
to execute arbitrary HTML and script code in a user's browser session in context of an affected site.

  - An error in the handling of sessions can be exploited to hijack another user's session by tricking the user
into logging in after following a specially crafted link." );
	script_tag( name: "summary", value: "This host is running HP SiteScope and is prone to cross-site scripting
and session fixation vulnerabilities." );
	script_tag( name: "solution", value: "Apply the patch from below link." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less_equal( version: version, test_version: "9.54" ) || version_in_range( version: version, test_version: "11.0", test_version2: "11.10" ) || version_in_range( version: version, test_version: "10.0", test_version2: "10.14" )){
	security_message( port: port );
}

