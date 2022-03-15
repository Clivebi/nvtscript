if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101017" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-03-16 23:15:41 +0100 (Mon, 16 Mar 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2003-0223", "CVE-2003-0224", "CVE-2003-0225", "CVE-2003-0226" );
	script_name( "Microsoft MS03-018 security check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Christian Eric Edjenguele <christian.edjenguele@owasp.org>" );
	script_family( "Windows : Microsoft Bulletins" );
	script_xref( name: "URL", value: "http://www.microsoft.com/downloads/details.aspx?FamilyId=1DBC1914-98E9-4DED-ADBF-E9B374A1F79D&displaylang=en" );
	script_xref( name: "URL", value: "http://www.microsoft.com/downloads/details.aspx?FamilyId=2F5D9852-4ADD-44F8-8715-AC3D7D7D94BF&displaylang=en" );
	script_xref( name: "URL", value: "http://www.microsoft.com/downloads/details.aspx?FamilyId=77CFE3EF-C5C5-401C-BC12-9F08154A5007&displaylang=en" );
	script_xref( name: "URL", value: "http://www.microsoft.com/downloads/details.aspx?FamilyId=86F4407E-B9BF-4490-9421-008407578D11&displaylang=en" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/241211" );
	script_tag( name: "solution", value: "Microsoft has released a patch to correct these issues

  There is a dependency associated with this patch - it requires the patch from Microsoft Security Bulletin MS02-050 to be installed.
  If this patch is installed and MS02-050 is not present, client side certificates will be rejected.
  This functionality can be restored by installing the MS02-050 patch." );
	script_tag( name: "summary", value: "A Cross-Site Scripting(XSS)vulnerability affecting IIS 4.0, 5.0 and 5.1 involving the error message that's returned to advise that a
  requested URL has been redirected. An attacker who was able to lure a user into clicking a link on his or her web site could relay a request containing script to a
  third-party web site running IIS, thereby causing the third-party site's response (still including the script) to be sent to the user.
  The script would then render using the security settings of the third-party site rather than the attacker's.

  A buffer overrun that results because IIS 5.0 does not correctly validate requests for certain types of web pages known as server side includes.

  A denial of service vulnerability that results because of a flaw in the way IIS 4.0 and 5.0 allocate memory requests when constructing
  headers to be returned to a web client.

  A denial of service vulnerability that results because IIS 5.0 and 5.1 do not correctly handle an error condition when
  an overly long WebDAV request is passed to them. As a result an attacker could cause IIS to fail." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

