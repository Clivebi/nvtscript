if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802505" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_cve_id( "CVE-2011-3991" );
	script_bugtraq_id( 50412 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "creation_date", value: "2011-11-08 16:10:17 +0530 (Tue, 08 Nov 2011)" );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_name( "FFFTP Untrusted Search Path Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46649" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/71020" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN62336482/index.html" );
	script_xref( name: "URL", value: "http://jvndb.jvn.jp/ja/contents/2011/JVNDB-2011-000091.html" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_ffftp_detect.sc" );
	script_mandatory_keys( "FFFTP/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute an arbitrary program
  in the context of the user running the affected application." );
	script_tag( name: "affected", value: "FFFTP version 1.98a and prior on windows" );
	script_tag( name: "insight", value: "The flaw is due to an error in application, loading executables
  (e.g. notepad.exe) in an insecure manner." );
	script_tag( name: "solution", value: "Upgrade to the FFFTP version 1.98b or later." );
	script_tag( name: "summary", value: "The host is running FFFTP and is prone to untrusted search path
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://sourceforge.jp/projects/ffftp/releases/" );
	exit( 0 );
}
require("version_func.inc.sc");
ftpVer = get_kb_item( "FFFTP/Ver" );
if(!ftpVer){
	exit( 0 );
}
if(version_is_less_equal( version: ftpVer, test_version: "1.98.1.0" )){
	report = report_fixed_ver( installed_version: ftpVer, vulnerable_range: "Less than or equal to 1.98.1.0" );
	security_message( port: 0, data: report );
}

