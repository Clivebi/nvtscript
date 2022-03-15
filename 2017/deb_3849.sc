if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703849" );
	script_version( "2021-09-08T14:01:33+0000" );
	script_cve_id( "CVE-2017-6410", "CVE-2017-8422" );
	script_name( "Debian Security Advisory DSA 3849-1 (kde4libs - security update)" );
	script_tag( name: "last_modification", value: "2021-09-08 14:01:33 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-12 00:00:00 +0200 (Fri, 12 May 2017)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3849.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "kde4libs on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 4:4.14.2-5+deb8u2.

For the unstable distribution (sid), these problems have been fixed in
version 4:4.14.26-2.

We recommend that you upgrade your kde4libs packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in kde4libs, the core libraries
for all KDE 4 applications. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2017-6410
Itzik Kotler, Yonatan Fridburg and Amit Klein of Safebreach Labs
reported that URLs are not sanitized before passing them to
FindProxyForURL, potentially allowing a remote attacker to obtain
sensitive information via a crafted PAC file.

CVE-2017-8422
Sebastian Krahmer from SUSE discovered that the KAuth framework
contains a logic flaw in which the service invoking dbus is not
properly checked. This flaw allows spoofing the identity of the
caller and gaining root privileges from an unprivileged account." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "kdelibs-bin", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kdelibs5-data", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kdelibs5-dbg", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kdelibs5-dev", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kdelibs5-plugins", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kdoctools", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkcmutils4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkde3support4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkdeclarative5", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkdecore5", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkdesu5", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkdeui5", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkdewebkit5", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkdnssd4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkemoticons4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkfile4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkhtml5", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkidletime4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkimproxy4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkio5", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkjsapi4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkjsembed4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkmediaplayer4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libknewstuff2-4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libknewstuff3-4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libknotifyconfig4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkntlm4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkparts4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkprintutils4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkpty4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkrosscore4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkrossui4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libktexteditor4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkunitconversion4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkutils4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnepomuk4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnepomukquery4a", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnepomukutils4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libplasma3", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsolid4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libthreadweaver4", ver: "4:4.14.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
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

