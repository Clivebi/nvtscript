if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704302" );
	script_version( "2021-06-21T12:14:05+0000" );
	script_cve_id( "CVE-2018-16947", "CVE-2018-16948", "CVE-2018-16949" );
	script_name( "Debian Security Advisory DSA 4302-1 (openafs - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 12:14:05 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-23 00:00:00 +0200 (Sun, 23 Sep 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4302.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "openafs on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 1.6.20-2+deb9u2.

We recommend that you upgrade your openafs packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/openafs" );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in openafs, an implementation of
the distributed filesystem AFS. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2018-16947
Jeffrey Altman reported that the backup tape controller (butc)
process does accept incoming RPCs but does not require (or allow
for) authentication of those RPCs, allowing an unauthenticated
attacker to perform volume operations with administrator
credentials.

CVE-2018-16948
Mark Vitale reported that several RPC server routines do not fully
initialize output variables, leaking memory contents (from both
the stack and the heap) to the remote caller for
otherwise-successful RPCs.

CVE-2018-16949
Mark Vitale reported that an unauthenticated attacker can consume
large amounts of server memory and network bandwidth via
specially crafted requests, resulting in denial of service to
legitimate clients." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libafsauthent1", ver: "1.6.20-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libafsrpc1", ver: "1.6.20-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkopenafs1", ver: "1.6.20-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenafs-dev", ver: "1.6.20-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-openafs-kaserver", ver: "1.6.20-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-client", ver: "1.6.20-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-dbserver", ver: "1.6.20-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-doc", ver: "1.6.20-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-fileserver", ver: "1.6.20-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-fuse", ver: "1.6.20-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-kpasswd", ver: "1.6.20-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-krb5", ver: "1.6.20-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-modules-dkms", ver: "1.6.20-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-modules-source", ver: "1.6.20-2+deb9u2", rls: "DEB9" ) )){
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

