if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800429" );
	script_version( "2021-10-05T12:25:15+0000" );
	script_tag( name: "deprecated", value: TRUE );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2010-01-20 08:21:11 +0100 (Wed, 20 Jan 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-0249" );
	script_bugtraq_id( 37815 );
	script_name( "Microsoft Internet Explorer RCE Vulnerability (979352)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/979352" );
	script_xref( name: "URL", value: "http://www.microsoft.com/technet/security/advisory/979352.mspx" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code
  via specially crafted attack." );
	script_tag( name: "affected", value: "Internet Explorer Version 6.x, 7.x and 8.x." );
	script_tag( name: "insight", value: "An invalid pointer reference error exists under certain conditions letting an
  invalid pointer to be accessed after an object is deleted." );
	script_tag( name: "summary", value: "Internet Explorer is prone to a remote code execution (RCE) vulnerability.

  This VT has been replaced by OID:1.3.6.1.4.1.25623.1.0.901097." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
exit( 66 );

