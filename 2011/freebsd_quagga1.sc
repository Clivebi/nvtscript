if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69384" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-1674", "CVE-2010-1675" );
	script_name( "FreeBSD Ports: quagga" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: quagga

CVE-2010-1674
The extended-community parser in bgpd in Quagga before 0.99.18 allows
remote attackers to cause a denial of service (NULL pointer
dereference and application crash) via a malformed Extended
Communities attribute.

CVE-2010-1675
bgpd in Quagga before 0.99.18 allows remote attackers to cause a
denial of service (session reset) via a malformed AS_PATHLIMIT path
attribute." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.quagga.net/news2.php?y=2011&m=3&d=21#id1300723200" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/b2a40507-5c88-11e0-9e85-00215af774f0.html" );
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
bver = portver( pkg: "quagga" );
if(!isnull( bver ) && revcomp( a: bver, b: "0.99.17_6" ) < 0){
	txt += "Package quagga version " + bver + " is installed which is known to be vulnerable.\n";
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

