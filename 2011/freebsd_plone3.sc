if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68947" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-03-05 22:25:39 +0100 (Sat, 05 Mar 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0720" );
	script_bugtraq_id( 46102 );
	script_name( "FreeBSD Ports: plone" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  plone
   plone3

CVE-2011-0720
Unspecified vulnerability in Plone 2.5 through 4.0 allows remote
attackers to obtain administrative access, read or create arbitrary
content, and change the site skin via unknown vectors." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://plone.org/products/plone/security/advisories/cve-2011-0720" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/7c492ea2-3566-11e0-8e81-0022190034c0.html" );
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
bver = portver( pkg: "plone" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.5" ) >= 0){
	txt += "Package plone version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "plone3" );
if(!isnull( bver ) && revcomp( a: bver, b: "3" ) >= 0){
	txt += "Package plone3 version " + bver + " is installed which is known to be vulnerable.\n";
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

