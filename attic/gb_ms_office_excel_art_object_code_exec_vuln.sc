if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801597" );
	script_version( "2021-10-05T12:25:15+0000" );
	script_tag( name: "deprecated", value: TRUE );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)" );
	script_cve_id( "CVE-2011-0980" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft Office Excel 2003 Invalid Object Type RCE Vulnerability" );
	script_xref( name: "URL", value: "http://zerodayinitiative.com/advisories/ZDI-11-043/" );
	script_xref( name: "URL", value: "http://dvlabs.tippingpoint.com/blog/2011/02/07/zdi-disclosure-microsoft" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  codes, cause memory corruption and other attacks in the context of the
  application through crafting malicious codes inside a Excel file." );
	script_tag( name: "affected", value: "Microsoft Office Excel 2003." );
	script_tag( name: "insight", value: "The flaw occurs when parsing a document with a malformed Excel
  document. When parsing an office art object, the application fails to put appropriate trust parameters." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "Microsoft Office Excel is prone to multiple remote code execution (RCE)
  vulnerabilities.

  This VT has been replaced by VT (OID:1.3.6.1.4.1.25623.1.0.902410)." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
exit( 66 );

