if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69365" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "FreeBSD Ports: asterisk16" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  asterisk16

  asterisk18" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2011-003.html" );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2011-004.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/bfe9c75e-5028-11e0-b2d2-00215c6a37bb.html" );
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
bver = portver( pkg: "asterisk16" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.6" ) > 0 && revcomp( a: bver, b: "1.6.2.17.1" ) < 0){
	txt += "Package asterisk16 version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "asterisk18" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.8" ) > 0 && revcomp( a: bver, b: "1.8.3.1" ) < 0){
	txt += "Package asterisk18 version " + bver + " is installed which is known to be vulnerable.\n";
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

