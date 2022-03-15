if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800220" );
	script_version( "$Revision: 12694 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-06 16:28:57 +0100 (Thu, 06 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2009-01-08 14:06:04 +0100 (Thu, 08 Jan 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5839" );
	script_bugtraq_id( 31294 );
	script_name( "FoxMail Client Buffer Overflow vulnerability" );
	script_xref( name: "URL", value: "http://www.sebug.net/exploit/4681" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/45343" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_foxmail_detect.sc" );
	script_mandatory_keys( "Foxmail/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to insert a long crafted
  URI in the MAILTO field and can cause a stack overflow to the application." );
	script_tag( name: "affected", value: "Foxmail version 6.5 or prior on Windows." );
	script_tag( name: "insight", value: "This flaw is due to lack of sanitization and boundary check in the user
  supplied data which can be exploited by adding a long URL length in the
  HREF attribute of an A element." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with FoxMail Client and is prone to Buffer
  Overflow Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
CPE = "cpe:/a:tencent:foxmail";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "6.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.5" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

