CPE = "cpe:/a:mozilla:bugzilla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801413" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)" );
	script_cve_id( "CVE-2009-3166" );
	script_bugtraq_id( 36372 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Bugzilla URL Password Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36718" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2009/Sep/1022902.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "bugzilla_detect.sc" );
	script_mandatory_keys( "bugzilla/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to read sensitive
  information via the HTTP 'Referrer' header." );
	script_tag( name: "affected", value: "Bugzilla version 3.4rc1 to 3.4.1." );
	script_tag( name: "insight", value: "The flaw is caused because the application places a password in a 'URL' at the
  beginning of a login session that occurs immediately after a password reset,
  which allows context-dependent attackers to discover passwords." );
	script_tag( name: "solution", value: "Upgrade to Bugzilla version 3.4.2 or later." );
	script_tag( name: "summary", value: "This host is running Bugzilla and is prone to information disclosure
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.bugzilla.org/download/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( port: port, cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "3.4.rc1", test_version2: "3.4.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.4.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

