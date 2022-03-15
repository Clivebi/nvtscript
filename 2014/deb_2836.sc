if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702836" );
	script_version( "2019-12-10T07:34:00+0000" );
	script_cve_id( "CVE-2013-6888", "CVE-2013-7325" );
	script_name( "Debian Security Advisory DSA 2836-1 (devscripts - arbitrary code execution)" );
	script_tag( name: "last_modification", value: "2019-12-10 07:34:00 +0000 (Tue, 10 Dec 2019)" );
	script_tag( name: "creation_date", value: "2014-01-05 00:00:00 +0100 (Sun, 05 Jan 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2836.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "devscripts on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 2.12.6+deb7u2.

For the testing distribution (jessie) and the unstable distribution
(sid), these problems have been fixed in version 2.13.9.

We recommend that you upgrade your devscripts packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in uscan, a tool to scan
upstream sites for new releases of packages, which is part of the
devscripts package. An attacker controlling a website from which uscan
would attempt to download a source tarball could execute arbitrary code
with the privileges of the user running uscan.

The Common Vulnerabilities and Exposures project id CVE-2013-6888
has
been assigned to identify them." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "devscripts", ver: "2.12.6+deb7u2", rls: "DEB7" ) ) != NULL){
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

