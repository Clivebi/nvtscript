if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702761" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4956", "CVE-2013-4761" );
	script_name( "Debian Security Advisory DSA 2761-1 (puppet - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-19 00:00:00 +0200 (Thu, 19 Sep 2013)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2761.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "puppet on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 2.7.23-1~deb7u1.

For the testing distribution (jessie) and the unstable distribution (sid),
these problems have been fixed in version 3.2.4-1.

We recommend that you upgrade your puppet packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in puppet, a centralized
configuration management system. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2013-4761The resource_type
service (disabled by default) could be used to
make puppet load arbitrary Ruby code from puppet master's file
system.

CVE-2013-4956
Modules installed with the Puppet Module Tool might be installed
with weak permissions, possibly allowing local users to read or
modify them.

The stable distribution (wheezy) has been updated to version 2.7.33 of
puppet. This version includes the patches for all the previous DSAs
related to puppet in wheezy. In this version, the puppet report format
is now correctly reported as version 3.

It is to be expected that future DSAs for puppet update to a newer,
bug fix-only, release of the 2.7 branch.

The oldstable distribution (squeeze) has not been updated for this
advisory: as of this time there is no fix for
CVE-2013-4761 and the package is not affected by
CVE-2013-4956
." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "puppet", ver: "2.7.23-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-common", ver: "2.7.23-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-el", ver: "2.7.23-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-testsuite", ver: "2.7.23-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppetmaster", ver: "2.7.23-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppetmaster-common", ver: "2.7.23-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppetmaster-passenger", ver: "2.7.23-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-puppet", ver: "2.7.23-1~deb7u1", rls: "DEB7" ) ) != NULL){
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

