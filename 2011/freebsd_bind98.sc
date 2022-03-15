if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69994" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_cve_id( "CVE-2011-2465" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:N/A:P" );
	script_name( "FreeBSD Ports: bind98" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: bind98

CVE-2011-2465
Unspecified vulnerability in ISC BIND 9 9.8.0, 9.8.0-P1, 9.8.0-P2, and
9.8.1b1, when recursion is enabled and the Response Policy Zone (RPZ)
contains DNAME or certain CNAME records, allows remote attackers to
cause a denial of service (named daemon crash) via an unspecified
query." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://www.isc.org/software/bind/advisories/cve-2011-2465" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/4ccee784-a721-11e0-89b4-001ec9578670.html" );
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
bver = portver( pkg: "bind98" );
if(!isnull( bver ) && revcomp( a: bver, b: "9.8.0.4" ) < 0){
	txt += "Package bind98 version " + bver + " is installed which is known to be vulnerable.\n";
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

