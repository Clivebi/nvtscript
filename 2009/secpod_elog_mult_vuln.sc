CPE = "cpe:/a:stefan_ritt:elog_web_logbook";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901009" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-7004", "CVE-2008-0444", "CVE-2008-0445" );
	script_bugtraq_id( 27399 );
	script_name( "ELOG Remote Buffer Overflow and Cross Site Scripting Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_elog_detect.sc" );
	script_mandatory_keys( "ELOG/detected" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/39903" );
	script_xref( name: "URL", value: "https://midas.psi.ch/elog/download/ChangeLog" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2008/0265" );
	script_xref( name: "URL", value: "https://midas.psi.ch/elog/download/" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary scripting
  code, cause a denial of service or compromise a vulnerable system." );
	script_tag( name: "affected", value: "ELOG versions prior to 2.7.1." );
	script_tag( name: "insight", value: "The flaws are due to:

  - A buffer overflow error in 'elog.c' when processing malformed data.

  - An infinite loop in the 'replace_inline_img()' [elogd.c] function.

  - An input validation error when handling the 'subtext' parameter." );
	script_tag( name: "solution", value: "Upgrade ELOG Version to 2.7.1. Please see the
  references for more info." );
	script_tag( name: "summary", value: "This host has ELOG installed and is prone multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "2.7.1.2002" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.7.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

