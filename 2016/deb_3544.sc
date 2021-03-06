if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703544" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-2512", "CVE-2016-2513" );
	script_name( "Debian Security Advisory DSA 3544-1 (python-django - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-04-07 00:00:00 +0200 (Thu, 07 Apr 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3544.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|9|8)" );
	script_tag( name: "affected", value: "python-django on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 1.4.5-1+deb7u16.

For the stable distribution (jessie), these problems have been fixed in
version 1.7.7-1+deb8u4.

For the testing distribution (stretch), these problems have been fixed
in version 1.9.4-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.9.4-1.

We recommend that you upgrade your python-django packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered
in Django, a high-level Python web development framework. The Common Vulnerabilities
and Exposures project identifies the following problems:

CVE-2016-2512
Mark Striemer discovered that some user-supplied redirect URLs
containing basic authentication credentials are incorrectly handled,
potentially allowing a remote attacker to perform a malicious
redirect or a cross-site scripting attack.

CVE-2016-2513
Sjoerd Job Postmus discovered that Django allows user enumeration
through timing difference on password hasher work factor upgrades." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-django", ver: "1.4.5-1+deb7u16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-django-doc", ver: "1.4.5-1+deb7u16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-django", ver: "1.9.4-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-django-common", ver: "1.9.4-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-django-doc", ver: "1.9.4-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-django", ver: "1.9.4-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-django", ver: "1.7.7-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-django-common", ver: "1.7.7-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-django-doc", ver: "1.7.7-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-django", ver: "1.7.7-1+deb8u4", rls: "DEB8" ) ) != NULL){
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

