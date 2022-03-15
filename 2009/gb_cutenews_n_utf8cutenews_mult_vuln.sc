CPE = "cpe:/a:cutephp:cutenews";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801056" );
	script_version( "2020-10-22T09:21:24+0000" );
	script_tag( name: "last_modification", value: "2020-10-22 09:21:24 +0000 (Thu, 22 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-4113", "CVE-2009-4116", "CVE-2009-4115", "CVE-2009-4174", "CVE-2009-4175", "CVE-2009-4173", "CVE-2009-4172", "CVE-2009-4250", "CVE-2009-4249" );
	script_bugtraq_id( 36971 );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "CuteNews/UTF-8 CuteNews Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/54243" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/507782/100/0/threaded" );
	script_xref( name: "URL", value: "http://www.morningstarsecurity.com/advisories/MORNINGSTAR-2009-02-CuteNews.txt" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cutenews_detect.sc" );
	script_mandatory_keys( "cutenews/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to steal user
  credentials, disclose file contents, disclose the file path of the application, execute arbitrary commands." );
	script_tag( name: "affected", value: "CuteNews version 1.4.6 and UTF-8 CuteNews version prior to 8b." );
	script_tag( name: "insight", value: "- An improper validation of user-supplied input by the 'category.db.php'
  script via the Category Access field or Icon URL fields

  - An improper validation of user-supplied input by the 'data/ipban.php' script via the add_ip parameter.

  - An improper validation of user-supplied input by the 'Editnews module' via list or editnews parameters and
  'Options module' via save_con[skin] parameter.

  - An error in 'editusers' module within 'index.php' allows attackers to hijack the authentication of
  administrators for requests that create new users.

  - An error in 'from_date_day' parameter to 'search.php' which reveals the installation path in an error message.

  - An error in 'modified id' parameter in a 'doeditnews' action allows remote users with Journalist or Editor
  access to bypass administrative moderation and edit previously submitted articles.

  - An improper validation of user-supplied input by the result parameter to 'register.php', the user parameter to
  'search.php', the cat_msg, source_msg, postponed_selected, unapproved_selected, and news_per_page parameters in a
  list action to the editnews module of 'index.php' and the link tag in news comments

  - An error in lastusername and mod parameters to 'index.php' and the title parameter to 'search.php' it allow
  attackers to inject arbitrary web script or HTML" );
	script_tag( name: "summary", value: "The host is running CuteNews/UTF-8 CuteNews and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution", value: "For UTF-8 CuteNews Upgrade to version 8b or later.

  For CuteNews Upgrade to version 1.5.0.1 or later." );
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
utf = get_kb_item( "cutenews/utf-8" );
if( !utf ){
	if(version_is_less( version: version, test_version: "1.5.0.1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "1.5.0.1" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
else {
	if(version_is_less( version: version, test_version: "8b" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "8b" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

