if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800948" );
	script_version( "$Revision: 12694 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-06 16:28:57 +0100 (Thu, 06 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3483" );
	script_name( "CuteFTP Heap Based Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_cuteftp_detect.sc" );
	script_mandatory_keys( "CuteFTP/Win/Ver" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36874" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53487" );
	script_xref( name: "URL", value: "http://www.packetstormsecurity.org/0909-exploits/Dr_IDE-CuteFTP_FTP_8.3.3-PoC.py.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary code and potentially compromise a user's system." );
	script_tag( name: "affected", value: "CuteFTP Home/Pro/Lite 8.3.3, 8.3.3.54 on Windows." );
	script_tag( name: "insight", value: "The flaw is due to error in 'Create New Site' feature when
  connecting to sites having an overly long label. This can be exploited to
  corrupt heap memory by tricking a user into importing a malicious site list and
  connecting to a site having an overly long label." );
	script_tag( name: "solution", value: "Upgrade to version 8.3.4 or later." );
	script_tag( name: "summary", value: "The host is installed with CuteFTP and is prone to buffer overflow
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.cuteftp.com/downloads" );
	exit( 0 );
}
require("version_func.inc.sc");
cVer = make_list();
for type in make_list( "Home",
	 "Lite",
	 "Professional" ) {
	tmpVer = get_kb_item( "CuteFTP/" + type + "/Ver" );
	if(!isnull( tmpVer )){
		cVer = make_list( cVer,
			 tmpVer );
	}
}
for ver in cVer {
	if(version_is_equal( version: ver, test_version: "8.3.3" ) || version_is_equal( version: ver, test_version: "8.3.3.54" )){
		security_message( port: 0 );
		exit( 0 );
	}
}
exit( 99 );

