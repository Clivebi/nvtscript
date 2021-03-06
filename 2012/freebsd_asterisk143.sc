if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71295" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "FreeBSD Ports: asterisk14" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  asterisk14

  asterisk16

  asterisk18

  asterisk10" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2012-002.html" );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2012-003.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/0d530174-6eef-11e1-afd6-14dae9ebcf89.html" );
	script_tag( name: "summary", value: "The remote host is missing an update to the system
  as announced in the referenced advisory." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-bsd.inc.sc");
vuln = FALSE;
txt = "";
bver = portver( pkg: "asterisk14" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.4" ) > 0 && revcomp( a: bver, b: "1.4.44" ) < 0){
	txt += "Package asterisk14 version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "asterisk16" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.6" ) > 0 && revcomp( a: bver, b: "1.6.2.23" ) < 0){
	txt += "Package asterisk16 version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "asterisk18" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.8" ) > 0 && revcomp( a: bver, b: "1.8.10.1" ) < 0){
	txt += "Package asterisk18 version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "asterisk10" );
if(!isnull( bver ) && revcomp( a: bver, b: "10" ) > 0 && revcomp( a: bver, b: "10.2.1" ) < 0){
	txt += "Package asterisk10 version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if( vuln ){
	security_message( data: txt );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

