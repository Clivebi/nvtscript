if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71255" );
	script_cve_id( "CVE-2012-1906", "CVE-2012-1986", "CVE-2012-1987", "CVE-2012-1988" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:56:51 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Debian Security Advisory DSA 2451-1 (puppet)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202451-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in puppet, a centralized
configuration management system.  The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2012-1906

Puppet is using predictable temporary file names when downloading
Mac OS X package files.  This allows a local attacker to either
overwrite arbitrary files on the system or to install an arbitrary
package.

CVE-2012-1986

When handling requests for a file from a remote filebucket, puppet
can be tricked into overwriting its defined location for filebucket
storage.  This allows an authorized attacker with access to the puppet
master to read arbitrary files.

CVE-2012-1987

Puppet is incorrectly handling filebucket store requests.  This allows
an attacker to perform denial of service attacks against puppet by
resource exhaustion.

CVE-2012-1988

Puppet is incorrectly handling filebucket requests.  This allows an
attacker with access to the certificate on the agent and an unprivileged
account on puppet master to execute arbitrary code via crafted file
path names and making a filebucket request.


For the stable distribution (squeeze), this problem has been fixed in
version 2.6.2-5+squeeze5.

For the testing distribution (wheezy), this problem has been fixed in
version 2.7.13-1.

For the unstable distribution (sid), this problem has been fixed in
version 2.7.13-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your puppet packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to puppet
announced via advisory DSA 2451-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "puppet", ver: "2.6.2-5+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-common", ver: "2.6.2-5+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-el", ver: "2.6.2-5+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-testsuite", ver: "2.6.2-5+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppetmaster", ver: "2.6.2-5+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-puppet", ver: "2.6.2-5+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet", ver: "2.7.13-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-common", ver: "2.7.13-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-el", ver: "2.7.13-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-testsuite", ver: "2.7.13-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppetmaster", ver: "2.7.13-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppetmaster-common", ver: "2.7.13-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppetmaster-passenger", ver: "2.7.13-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-puppet", ver: "2.7.13-1", rls: "DEB7" ) ) != NULL){
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

