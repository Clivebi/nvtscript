if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72629" );
	script_cve_id( "CVE-2012-5468" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-12-04 11:43:52 -0500 (Tue, 04 Dec 2012)" );
	script_name( "FreeBSD Ports: bogofilter" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  bogofilter
   bogofilter-sqlite
   bogofilter-tc" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://bogofilter.sourceforge.net/security/bogofilter-SA-2012-01" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/f524d8e0-3d83-11e2-807a-080027ef73ec.html" );
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
bver = portver( pkg: "bogofilter" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2.3" ) < 0){
	txt += "Package bogofilter version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "bogofilter-sqlite" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2.3" ) < 0){
	txt += "Package bogofilter-sqlite version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "bogofilter-tc" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2.3" ) < 0){
	txt += "Package bogofilter-tc version " + bver + " is installed which is known to be vulnerable.\\n";
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

