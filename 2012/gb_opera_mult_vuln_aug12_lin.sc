if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803002" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_bugtraq_id( 54782, 54788, 54780 );
	script_cve_id( "CVE-2012-4142", "CVE-2012-4143", "CVE-2012-4144", "CVE-2012-4145", "CVE-2012-4146" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-08-08 10:50:33 +0530 (Wed, 08 Aug 2012)" );
	script_name( "Opera Multiple Vulnerabilities - August12 (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50044" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1025/" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1026/" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1027/" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/unix/1201/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_opera_detection_linux_900037.sc" );
	script_mandatory_keys( "Opera/Linux/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  script code, disclose sensitive information, or cause a denial of service." );
	script_tag( name: "affected", value: "Opera version prior to 12.01 on Linux" );
	script_tag( name: "insight", value: "- Multiple unspecified errors.

  - An error when certain characters in HTML documents are ignored under some
    circumstances, which allows to conduct XSS attacks.

  - The improper implementation of download dialog feature, which allows
    attackers to trick users into downloading and executing arbitrary files
    via a small window for the download dialog.

  - Fails to escape characters in DOM elements, which allows to conduct
    XSS attacks.

  - An error caused via a crafted web site on Lenovos 'Shop now' page." );
	script_tag( name: "solution", value: "Upgrade to Opera version 12.01 or later." );
	script_tag( name: "summary", value: "This host is installed with Opera and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Linux/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "12.01" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "12.01" );
	security_message( port: 0, data: report );
}

