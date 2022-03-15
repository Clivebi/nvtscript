if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69599" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-0465" );
	script_name( "FreeBSD Ports: xrdb" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: xrdb

CVE-2011-0465
xrdb.c in xrdb before 1.0.9 in X.Org X11R7.6 and earlier allows remote
attackers to execute arbitrary commands via shell metacharacters in a
hostname obtained from a (1) DHCP or (2) XDMCP message." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://lists.freedesktop.org/archives/xorg-announce/2011-April/001636.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/2eccb24f-61c0-11e0-b199-0015f2db7bde.html" );
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
bver = portver( pkg: "xrdb" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.0.6_1" ) < 0){
	txt += "Package xrdb version " + bver + " is installed which is known to be vulnerable.\n";
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

