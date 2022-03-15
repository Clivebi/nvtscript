if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71491" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-2978" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:12:22 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2515-1 (nsd3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202515-1" );
	script_tag( name: "insight", value: "Marek Vavrusa and Lubos Slovak discovered that NSD, an authoritative
domain name server, is not properly handling non-standard DNS packets.
his can result in a NULL pointer dereference and crash the handling
process.  A remote attacker can abuse this flaw to perform denial of
service attacks.


For the stable distribution (squeeze), this problem has been fixed in
version 3.2.5-1.squeeze2.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 3.2.12-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your nsd3 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to nsd3
announced via advisory DSA 2515-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "nsd3", ver: "3.2.5-1.squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

