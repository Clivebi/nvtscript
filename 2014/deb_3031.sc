if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703031" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-6273" );
	script_name( "Debian Security Advisory DSA 3031-1 (apt - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-09-23 00:00:00 +0200 (Tue, 23 Sep 2014)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3031.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "apt on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 0.9.7.9+deb7u5.

We recommend that you upgrade your apt packages." );
	script_tag( name: "summary", value: "The Google Security Team discovered a buffer overflow vulnerability in
the HTTP transport code in apt-get. An attacker able to
man-in-the-middle a HTTP request to an apt repository can trigger the
buffer overflow, leading to a crash of the http
apt method binary, or
potentially to arbitrary code execution.

Two regression fixes were included in this update:

Fix regression from the previous update in DSA-3025-1 when the custom
apt configuration option for Dir::state::lists is set to a relative
path (#762160).

Fix regression in the reverification handling of cdrom: sources that
may lead to incorrect hashsum warnings. Affected users need to run
'apt-cdrom add' again after the update was applied." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "apt", ver: "0.9.7.9+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apt-doc", ver: "0.9.7.9+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apt-transport-https", ver: "0.9.7.9+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apt-utils", ver: "0.9.7.9+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-inst1.5", ver: "0.9.7.9+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-pkg-dev", ver: "0.9.7.9+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-pkg-doc", ver: "0.9.7.9+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-pkg4.12", ver: "0.9.7.9+deb7u5", rls: "DEB7" ) ) != NULL){
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

