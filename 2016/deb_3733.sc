if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703733" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-1252" );
	script_name( "Debian Security Advisory DSA 3733-1 (apt - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-12-13 00:00:00 +0100 (Tue, 13 Dec 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3733.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "apt on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 1.0.9.8.4.

For the unstable distribution (sid), this problem has been fixed in
version 1.4~beta2.

We recommend that you upgrade your apt packages." );
	script_tag( name: "summary", value: "Jann Horn of Google Project Zero discovered
that APT, the high level package manager, does not properly handle errors when
validating signatures on InRelease files. An attacker able to man-in-the-middle
HTTP requests to an apt repository that uses InRelease files
(clearsigned Release files), can take advantage of this flaw to
circumvent the signature of the InRelease file, leading to arbitrary
code execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "apt", ver: "1.0.9.8.4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apt-doc", ver: "1.0.9.8.4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apt-transport-https", ver: "1.0.9.8.4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apt-utils", ver: "1.0.9.8.4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-inst1.5:amd64", ver: "1.0.9.8.4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-inst1.5:i386", ver: "1.0.9.8.4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-pkg-dev:amd64", ver: "1.0.9.8.4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-pkg-dev:i386", ver: "1.0.9.8.4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-pkg-doc", ver: "1.0.9.8.4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-pkg4.12:amd64", ver: "1.0.9.8.4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-pkg4.12:i386", ver: "1.0.9.8.4", rls: "DEB8" ) ) != NULL){
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

