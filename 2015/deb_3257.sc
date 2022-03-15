if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703257" );
	script_version( "2020-02-28T09:03:19+0000" );
	script_cve_id( "CVE-2014-9390", "CVE-2014-9462" );
	script_name( "Debian Security Advisory DSA 3257-1 (mercurial - security update)" );
	script_tag( name: "last_modification", value: "2020-02-28 09:03:19 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-05-11 00:00:00 +0200 (Mon, 11 May 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3257.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "mercurial on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 2.2.2-4+deb7u1. This update also includes
a fix for CVE-2014-9390
previously scheduled for the next wheezy point release.

For the stable distribution (jessie), this problem has been fixed in
version 3.1.2-2+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 3.4-1.

We recommend that you upgrade your mercurial packages." );
	script_tag( name: "summary", value: "Jesse Hertz of Matasano Security
discovered that Mercurial, a distributed version control system, is prone to a
command injection vulnerability via a crafted repository name in a clone
command." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "mercurial", ver: "2.2.2-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mercurial-common", ver: "2.2.2-4+deb7u1", rls: "DEB7" ) ) != NULL){
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

