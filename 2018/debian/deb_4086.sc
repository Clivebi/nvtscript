if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704086" );
	script_version( "2021-06-18T11:51:03+0000" );
	script_cve_id( "CVE-2017-15412" );
	script_name( "Debian Security Advisory DSA 4086-1 (libxml2 - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:51:03 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-13 00:00:00 +0100 (Sat, 13 Jan 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-25 11:35:00 +0000 (Thu, 25 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4086.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "libxml2 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 2.9.1+dfsg1-5+deb8u6.

For the stable distribution (stretch), this problem has been fixed in
version 2.9.4+dfsg1-2.2+deb9u2.

We recommend that you upgrade your libxml2 packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/libxml2" );
	script_tag( name: "summary", value: "Nick Wellnhofer discovered that certain function calls inside XPath
predicates can lead to use-after-free and double-free errors when
executed by libxml2's XPath engine via an XSLT transformation." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxml2", ver: "2.9.4+dfsg1-2.2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-dbg", ver: "2.9.4+dfsg1-2.2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-dev", ver: "2.9.4+dfsg1-2.2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-doc", ver: "2.9.4+dfsg1-2.2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-utils", ver: "2.9.4+dfsg1-2.2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-utils-dbg", ver: "2.9.4+dfsg1-2.2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-libxml2", ver: "2.9.4+dfsg1-2.2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-libxml2-dbg", ver: "2.9.4+dfsg1-2.2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-libxml2", ver: "2.9.4+dfsg1-2.2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-libxml2-dbg", ver: "2.9.4+dfsg1-2.2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2", ver: "2.9.1+dfsg1-5+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-dbg", ver: "2.9.1+dfsg1-5+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-dev", ver: "2.9.1+dfsg1-5+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-doc", ver: "2.9.1+dfsg1-5+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-utils", ver: "2.9.1+dfsg1-5+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-utils-dbg", ver: "2.9.1+dfsg1-5+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-libxml2", ver: "2.9.1+dfsg1-5+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-libxml2-dbg", ver: "2.9.1+dfsg1-5+deb8u6", rls: "DEB8" ) )){
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

