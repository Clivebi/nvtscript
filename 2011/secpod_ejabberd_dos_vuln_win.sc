if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902527" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)" );
	script_cve_id( "CVE-2011-1753" );
	script_bugtraq_id( 48072 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "ejabberd XML Parsing Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44807" );
	script_xref( name: "URL", value: "http://www.ejabberd.im/ejabberd-2.1.7" );
	script_xref( name: "URL", value: "http://www.process-one.net/en/ejabberd/release_notes/release_note_ejabberd_2.1.7/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_ejabberd_detect_win.sc" );
	script_mandatory_keys( "ejabberd/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to cause a denial of service." );
	script_tag( name: "affected", value: "ejabberd versions before 2.1.7 and 3.x before 3.0.0-alpha-3" );
	script_tag( name: "insight", value: "The flaw is due to an error within the parsing of certain XML input,
  which can be exploited to cause a high CPU and memory consumption via a
  crafted XML document containing a large number of nested entity references." );
	script_tag( name: "solution", value: "Upgrade to ejabberd version 2.1.7, 3.0.0-alpha-3 or later." );
	script_tag( name: "summary", value: "This host is installed with ejabberd and is prone to denial of
  service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ver = get_kb_item( "ejabberd/Win/Ver" );
if(ver){
	ver = ereg_replace( pattern: "-", replace: ".", string: ver );
	if(version_is_less( version: ver, test_version: "2.1.7" ) || version_in_range( version: ver, test_version: "3.0.0", test_version2: "3.0.0.alpha.2" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

