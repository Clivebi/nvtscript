if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70605" );
	script_tag( name: "creation_date", value: "2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-1944" );
	script_version( "$Revision: 11762 $" );
	script_name( "FreeBSD Ports: libxml" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  libxml
   libxml2

CVE-2011-1944
Integer overflow in xpath.c in libxml2 2.6.x through 2.6.32 and 2.7.x
through 2.7.8, and libxml 1.8.16 and earlier, allows context-dependent
attackers to cause a denial of service (crash) and possibly execute
arbitrary code via a crafted XML file that triggers a heap-based
buffer overflow when adding a new namespace node, related to handling
of XPath expressions." );
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
bver = portver( pkg: "libxml" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.8.17_5" ) < 0){
	txt += "Package libxml version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "libxml2" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.7.8" ) < 0){
	txt += "Package libxml2 version " + bver + " is installed which is known to be vulnerable.\n";
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

