if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70064" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-08-07 17:37:07 +0200 (Sun, 07 Aug 2011)" );
	script_cve_id( "CVE-2011-1411" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_name( "FreeBSD Ports: opensaml2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: opensaml2

CVE-2011-1411
** RESERVED **
This candidate has been reserved by an organization or individual that
will use it when announcing a new security problem.  When the
candidate has been publicized, the details for this candidate will be
provided." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://groups.google.com/a/shibboleth.net/group/announce/browse_thread/thread/cf3e0d76afbb57d9" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/9f14cb36-b6fc-11e0-a044-445c73746d79.html" );
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
bver = portver( pkg: "opensaml2" );
if(!isnull( bver ) && revcomp( a: bver, b: "0" ) > 0 && revcomp( a: bver, b: "2.4.3" ) < 0){
	txt += "Package opensaml2 version " + bver + " is installed which is known to be vulnerable.\n";
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

