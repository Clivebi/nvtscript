if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702751" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4233", "CVE-2013-4234" );
	script_name( "Debian Security Advisory DSA 2751-1 (libmodplug - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-04 00:00:00 +0200 (Wed, 04 Sep 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2751.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "libmodplug on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 1:0.8.8.1-1+squeeze2+git20130828.

For the stable distribution (wheezy), these problems have been fixed in
version 1:0.8.8.4-3+deb7u1+git20130828.

For the testing distribution (jessie), these problems will be fixed
soon.

For the unstable distribution (sid), these problems have been fixed in
version 1:0.8.8.4-4.

We recommend that you upgrade your libmodplug packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in libmodplug, a library for
mod music based on ModPlug, that might allow arbitrary code execution
when processing specially-crafted ABC files through applications using
the library, such as media players." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libmodplug-dev", ver: "1:0.8.8.1-1+squeeze2+git20130828", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmodplug1", ver: "1:0.8.8.1-1+squeeze2+git20130828", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmodplug-dev", ver: "1:0.8.8.4-3+deb7u1+git20130828", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmodplug1", ver: "1:0.8.8.4-3+deb7u1+git20130828", rls: "DEB7" ) ) != NULL){
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

