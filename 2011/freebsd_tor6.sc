if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68827" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-1676" );
	script_bugtraq_id( 45500 );
	script_name( "FreeBSD Ports: tor" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  tor
   tor-devel

CVE-2010-1676
Heap-based buffer overflow in Tor before 0.2.1.28 and 0.2.2.x before
0.2.2.20-alpha allows remote attackers to cause a denial of service
(daemon crash) or possibly execute arbitrary code via unspecified
vectors." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://gitweb.torproject.org/tor.git/blob/release-0.2.1:/ChangeLog" );
	script_xref( name: "URL", value: "https://gitweb.torproject.org/tor.git/blob/release-0.2.2:/ChangeLog" );
	script_xref( name: "URL", value: "http://archives.seul.org/or/announce/Dec-2010/msg00000.html" );
	script_xref( name: "URL", value: "http://archives.seul.org/or/talk/Dec-2010/msg00167.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/4bd33bc5-0cd6-11e0-bfa4-001676740879.html" );
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
bver = portver( pkg: "tor" );
if(!isnull( bver ) && revcomp( a: bver, b: "0.2.1.28" ) < 0){
	txt += "Package tor version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "tor-devel" );
if(!isnull( bver ) && revcomp( a: bver, b: "0.2.2.20-alpha" ) < 0){
	txt += "Package tor-devel version " + bver + " is installed which is known to be vulnerable.\n";
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

