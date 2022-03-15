if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70234" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Debian Security Advisory DSA 2299-1 (ca-certificates)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202299-1" );
	script_tag( name: "insight", value: "An unauthorized SSL certificate has been found in the wild issued
the DigiNotar Certificate Authority, obtained through a security
compromise with said company. Debian, like other software
distributors, has as a precaution decided to disable the DigiNotar
Root CA by default in its ca-certificates bundle.

For other software in Debian that ships a CA bundle, like the
Mozilla suite, updates are forthcoming.

For the oldstable distribution (lenny), the ca-certificates package
does not contain this root CA.

For the stable distribution (squeeze), the root CA has been
disabled starting ca-certificates version 20090814+nmu3.

For the testing distribution (wheezy) and unstable distribution
(sid), the root CA has been disabled starting ca-certificates
version 20110502+nmu1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your ca-certificates packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to ca-certificates
announced via advisory DSA 2299-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ca-certificates", ver: "20090814+nmu3", rls: "DEB6" ) ) != NULL){
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

