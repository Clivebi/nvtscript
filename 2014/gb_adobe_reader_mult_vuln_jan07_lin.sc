CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804394" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2006-5857", "CVE-2007-0046", "CVE-2007-0047", "CVE-2007-0044" );
	script_bugtraq_id( 21858, 21981 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-04-11 18:00:34 +0530 (Fri, 11 Apr 2014)" );
	script_name( "Adobe Reader Multiple Vulnerabilities Jan07 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws exist due to:

  - Input passed to a hosted PDF file is not properly sanitised by the browser
plug-in before being returned to users.

  - Input passed to a hosted PDF file is not properly handled by the browser
plug-in." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause memory corruption,
execution of arbitrary code, execution of arbitrary script code in a user's
browser session in context of an affected site and conduct cross site request
forgery attacks." );
	script_tag( name: "affected", value: "Adobe Reader version 7.0.8 and prior on Linux." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 7.0.9 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/23483" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/31266" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb07-01.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_prdts_detect_lin.sc" );
	script_mandatory_keys( "Adobe/Reader/Linux/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "7.0.8" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "Less than or equal to 7.0.8" );
	security_message( port: 0, data: report );
	exit( 0 );
}

