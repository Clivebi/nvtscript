CPE = "cpe:/a:dokeos:dokeos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100200" );
	script_version( "2021-08-11T10:41:15+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 10:41:15 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2009-05-14 12:53:07 +0200 (Thu, 14 May 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-2004" );
	script_bugtraq_id( 34928 );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Dokeos <= 1.8.5 Multiple Remote Input Validation Vulnerabilities" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "gb_dokeos_http_detect.sc" );
	script_mandatory_keys( "dokeos/detected" );
	script_tag( name: "summary", value: "Dokeos is prone to multiple input-validation vulnerabilities,
  including SQL-injection, HTML-injection, cross-site scripting, and cross-site request-forgery
  issues." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Attackers can exploit these issues to execute arbitrary script
  code in the context of the webserver, compromise the application, obtain sensitive information,
  steal cookie-based authentication credentials from legitimate users of the site, modify the way
  the site is rendered, perform certain unauthorized actions in the context of a user, access or
  modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Dokeos 1.8.5 is affected, prior versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34928" );
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
if(version_is_less_equal( version: version, test_version: "1.8.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

