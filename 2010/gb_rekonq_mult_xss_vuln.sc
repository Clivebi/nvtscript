if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801422" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)" );
	script_cve_id( "CVE-2010-2536" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "rekonq 'Error Page' Cross-Site Scripting Vulnerabilities" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_rekonq_detect.sc" );
	script_mandatory_keys( "rekonq/Linux/Ver" );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in the handling of a URL associated with a nonexistent domain name
  which is related to 'webpage.cpp',

  - An error in handling of unspecified vectors related to 'webview.cpp'

  - An error in the handing of 'about:' views for favorites, bookmarks, closed
  tabs, and history." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to version 0.6 or later." );
	script_tag( name: "summary", value: "This host is installed with rekonq and is prone to cross-site
  scripting vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to crash fresh
  instance, inject the malicious content into error message, access the cookies
  when the hostname under which the cookies have been set." );
	script_tag( name: "affected", value: "Rekonq version 0.5 and prior." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40646" );
	script_xref( name: "URL", value: "https://bugs.kde.org/show_bug.cgi?id=217464" );
	script_xref( name: "URL", value: "http://marc.info/?l=oss-security&m=127971194610788&w=2" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/rekonq/files" );
	exit( 0 );
}
require("version_func.inc.sc");
rekonqVer = get_kb_item( "rekonq/Linux/Ver" );
if(!rekonqVer){
	exit( 0 );
}
if(version_is_less_equal( version: rekonqVer, test_version: "0.5.0" )){
	report = report_fixed_ver( installed_version: rekonqVer, vulnerable_range: "Less than or equal to 0.5.0" );
	security_message( port: 0, data: report );
}

