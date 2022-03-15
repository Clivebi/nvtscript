if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900043" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-09-02 07:39:00 +0200 (Tue, 02 Sep 2008)" );
	script_bugtraq_id( 30866 );
	script_cve_id( "CVE-2008-3282" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "package" );
	script_family( "General" );
	script_name( "OpenOffice rtl_allocateMemory() Remote Code Execution Vulnerability (Linux)" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rpms", "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/31640/" );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2008/2449" );
	script_tag( name: "summary", value: "This host has OpenOffice.Org installed, which is prone to remote
  code execution vulnerability." );
	script_tag( name: "insight", value: "The issue is due to a numeric truncation error within the rtl_allocateMemory()
  method in alloc_global.c file." );
	script_tag( name: "affected", value: "OpenOffice.org 2.4.1 and prior on Linux." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to OpenOffice.org Version 3.2.0 or later." );
	script_tag( name: "impact", value: "Attackers can cause an out of bounds array access by tricking a
  user into opening a malicious document, also allow execution of arbitrary code." );
	exit( 0 );
}
for item in get_kb_list( "ssh/login/rpms" ) {
	if(egrep( pattern: "^(O|o)pen(O|o)ffice.*?~([01]\\..*|2\\.([0-3][^0-9]|4(\\.[01])?[^.0-9]))", string: item )){
		security_message( port: 0 );
		exit( 0 );
	}
}

