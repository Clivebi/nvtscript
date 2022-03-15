if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801580" );
	script_version( "2021-10-05T12:25:15+0000" );
	script_tag( name: "deprecated", value: TRUE );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)" );
	script_cve_id( "CVE-2010-4701" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft Windows Fax Cover Page Editor BOF Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42747" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1024925" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15839/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/16024/" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_tag( name: "impact", value: "Successful exploitation will allow the attacker to cause a heap-based buffer
  overflow via a Fax Cover Page file containing specially crafted content." );
	script_tag( name: "affected", value: "Fax Services Cover Page Editor 5.2 r2 on,

  Microsoft Windows XP Service Pack 3 and prior.

  Microsoft Windows 2K3 Service Pack 2 and prior.

  Microsoft Windows 7" );
	script_tag( name: "insight", value: "The flaw is due to an input validation error and a use-after-free
  error in the Fax Cover Page Editor 'fxscover.exe' when a function
  'CDrawPoly::Serialize()' reads in data from a Fax Cover Page file ('.cov')." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "Fax Cover Page Editor is prone to multiple buffer overflow vulnerabilities.

  This VT has been replaced by OID:1.3.6.1.4.1.25623.1.0.902408." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
exit( 66 );

