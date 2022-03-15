CPE = "cpe:/a:nullsoft:winamp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804845" );
	script_version( "2021-08-13T07:21:38+0000" );
	script_cve_id( "CVE-2013-4694" );
	script_bugtraq_id( 60883 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 07:21:38 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-09-18 16:49:22 +0530 (Thu, 18 Sep 2014)" );
	script_name( "Winamp Libraries Multiple Buffer Overflow Vulnerability - Sep14" );
	script_tag( name: "summary", value: "This host is installed with Winamp and
  is prone to buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists as user-supplied input is not
  properly validated when handling a specially crafted overly long Skins directory
  name." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service or potentially allowing the execution
  of arbitrary code." );
	script_tag( name: "affected", value: "Winamp prior version 5.64 Build 3418" );
	script_tag( name: "solution", value: "Upgrade to Winamp version 5.64 Build 3418
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/85399" );
	script_xref( name: "URL", value: "http://forums.winamp.com/showthread.php?t=364291" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_winamp_detect.sc" );
	script_mandatory_keys( "Winamp/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "5.6.4.3418" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.6.4.3418" );
	security_message( port: 0, data: report );
	exit( 0 );
}

