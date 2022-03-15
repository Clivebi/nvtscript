if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703504" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_cve_id( "CVE-2016-2510" );
	script_name( "Debian Security Advisory DSA 3504-1 (bsh - security update)" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-03-08 12:37:51 +0530 (Tue, 08 Mar 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3504.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|7|9)" );
	script_tag( name: "affected", value: "bsh on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), this problem has been fixed
in version 2.0b4-12+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 2.0b4-15+deb8u1.

For the testing distribution (stretch) and unstable distribution
(sid), this problem has been fixed in version 2.0b4-16.

We recommend that you upgrade your bsh packages." );
	script_tag( name: "summary", value: "Alvaro Munoz and Christian Schneider discovered that BeanShell, an
embeddable Java source interpreter, could be leveraged to execute
arbitrary commands: applications including BeanShell in their
classpath are vulnerable to this flaw if they deserialize data from an
untrusted source." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "bsh", ver: "2.0b4-15+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bsh-doc", ver: "2.0b4-15+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bsh-src", ver: "2.0b4-15+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbsh-java", ver: "2.0b4-15+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bsh", ver: "2.0b4-12+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bsh-doc", ver: "2.0b4-12+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bsh-gcj", ver: "2.0b4-12+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bsh-src", ver: "2.0b4-12+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bsh", ver: "2.0b4-16", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bsh-doc", ver: "2.0b4-16", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bsh-src", ver: "2.0b4-16", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbsh-java", ver: "2.0b4-16", rls: "DEB9" ) ) != NULL){
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

