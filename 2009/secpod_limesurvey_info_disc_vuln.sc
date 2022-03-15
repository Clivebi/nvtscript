CPE = "cpe:/a:limesurvey:limesurvey";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900353" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-1604" );
	script_bugtraq_id( 34785 );
	script_name( "LimeSurvey Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34946" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/1219" );
	script_xref( name: "URL", value: "http://www.limesurvey.org/content/view/169/1/lang,en" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_limesurvey_detect.sc" );
	script_mandatory_keys( "limesurvey/installed" );
	script_require_ports( "Services/www", 80, 8080 );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker gain sensitive information by
  executing arbitrary commands inside the context of the affected web application." );
	script_tag( name: "affected", value: "LimeSurvey version prior to 1.82" );
	script_tag( name: "insight", value: "Error in a script in '/admin/remotecontrol/' and can be exploited to view and
  manipulate files, which may allow the execution of e.g. arbitrary PHP code." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to LimeSurvey version 1.82 or later." );
	script_tag( name: "summary", value: "imeSurvey is prone to Information Disclosure vulnerability." );
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
if(version_is_less( version: version, test_version: "1.82" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.82" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

