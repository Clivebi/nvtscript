if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703542" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-3068", "CVE-2016-3069", "CVE-2016-3630" );
	script_name( "Debian Security Advisory DSA 3542-1 (mercurial - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-04-05 00:00:00 +0200 (Tue, 05 Apr 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3542.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|7)" );
	script_tag( name: "affected", value: "mercurial on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 2.2.2-4+deb7u2.

For the stable distribution (jessie), these problems have been fixed in
version 3.1.2-2+deb8u2.

For the unstable distribution (sid), these problems have been fixed in
version 3.7.3-1.

We recommend that you upgrade your mercurial packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been
 discovered in Mercurial, a distributed version control system. The Common
Vulnerabilities and Exposures project identifies the following issues:

CVE-2016-3068
Blake Burkhart discovered that Mercurial allows URLs for Git
subrepositories that could result in arbitrary code execution on
clone.

CVE-2016-3069
Blake Burkhart discovered that Mercurial allows arbitrary code
execution when converting Git repositories with specially
crafted names.

CVE-2016-3630
It was discovered that Mercurial does not properly perform bounds-checking
in its binary delta decoder, which may be exploitable for
remote code execution via clone, push or pull." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "mercurial", ver: "3.1.2-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mercurial-common", ver: "3.1.2-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mercurial", ver: "2.2.2-4+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mercurial-common", ver: "2.2.2-4+deb7u2", rls: "DEB7" ) ) != NULL){
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

