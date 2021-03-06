if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703862" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_cve_id( "CVE-2017-2295" );
	script_name( "Debian Security Advisory DSA 3862-1 (puppet - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-25 00:00:00 +0200 (Thu, 25 May 2017)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-24 13:36:00 +0000 (Thu, 24 May 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3862.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "puppet on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 3.7.2-4+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 4.8.2-5.

We recommend that you upgrade your puppet packages." );
	script_tag( name: "summary", value: "It was discovered that unrestricted YAML deserialisation of data sent
from agents to the server in the Puppet configuration management system
could result in the execution of arbitrary code.

Note that this fix breaks backward compatibility with Puppet agents older
than 3.2.2 and there is no safe way to restore it. This affects puppet
agents running on Debian wheezy. We recommend to update to the
puppet version shipped in wheezy-backports." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "puppet", ver: "3.7.2-4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-common", ver: "3.7.2-4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-el", ver: "3.7.2-4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-testsuite", ver: "3.7.2-4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppetmaster", ver: "3.7.2-4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppetmaster-common", ver: "3.7.2-4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppetmaster-passenger", ver: "3.7.2-4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-puppet", ver: "3.7.2-4+deb8u1", rls: "DEB8" ) ) != NULL){
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

