if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68814" );
	script_version( "$Revision: 11768 $" );
	script_cve_id( "CVE-2011-0495" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 16:07:38 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_name( "FreeBSD Ports: asterisk14" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  asterisk14

  asterisk16
  asterisk18" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2011-001.pdf" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/5ab9fb2a-23a5-11e0-a835-0003ba02bf30.html" );
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
if(!isnull( bver ) && revcomp( a: bver, b: "1.4" ) > 0 && revcomp( a: bver, b: "1.4.39.1" ) < 0){
	txt += "Package asterisk14 version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "asterisk16" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.6" ) > 0 && revcomp( a: bver, b: "1.6.2.16.1" ) < 0){
	txt += "Package asterisk16 version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "asterisk18" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.8" ) > 0 && revcomp( a: bver, b: "1.8.2.2" ) < 0){
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

