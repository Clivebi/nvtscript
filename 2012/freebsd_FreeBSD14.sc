if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70743" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-2895" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)" );
	script_name( "FreeBSD Ports: FreeBSD" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: FreeBSD

CVE-2011-2895
The LZW decompressor in (1) the BufCompressedFill function in
fontfile/decompress.c in X.Org libXfont before 1.4.4 and (2)
compress/compress.c in 4.3BSD, as used in zopen.c in OpenBSD before
3.8, FreeBSD, NetBSD 4.0.x and 5.0.x before 5.0.3 and 5.1.x before
5.1.1, FreeType 2.1.9, and other products, does not properly handle
code words that are absent from the decompression table when
encountered, which allows context-dependent attackers to trigger an
infinite loop or a heap-based buffer overflow, and possibly execute
arbitrary code, via a crafted compressed stream, a related issue to
CVE-2006-1168 and CVE-2011-2896." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
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
bver = portver( pkg: "FreeBSD" );
if(!isnull( bver ) && revcomp( a: bver, b: "7.3" ) >= 0 && revcomp( a: bver, b: "7.3_7" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "7.4" ) >= 0 && revcomp( a: bver, b: "7.4_3" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "8.1" ) >= 0 && revcomp( a: bver, b: "8.1_5" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "8.2" ) >= 0 && revcomp( a: bver, b: "8.2_3" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\n";
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

