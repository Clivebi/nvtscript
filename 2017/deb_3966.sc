if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703966" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_cve_id( "CVE-2015-9096", "CVE-2016-7798", "CVE-2017-0899", "CVE-2017-0900", "CVE-2017-0901", "CVE-2017-0902", "CVE-2017-14064" );
	script_name( "Debian Security Advisory DSA 3966-1 (ruby2.3 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-05 00:00:00 +0200 (Tue, 05 Sep 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3966.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "ruby2.3 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 2.3.3-1+deb9u1. This update also hardens RubyGems against
malicious terminal escape sequences (CVE-2017-0899
).

We recommend that you upgrade your ruby2.3 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were discovered in the interpreter for the Ruby
language:

CVE-2015-9096
SMTP command injection in Net::SMTP.

CVE-2016-7798
Incorrect handling of initialization vector in the GCM mode in the
OpenSSL extension.

CVE-2017-0900
Denial of service in the RubyGems client.

CVE-2017-0901
Potential file overwrite in the RubyGems client.

CVE-2017-0902
DNS hijacking in the RubyGems client.

CVE-2017-14064
Heap memory disclosure in the JSON library." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libruby2.3", ver: "2.3.3-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby2.3", ver: "2.3.3-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby2.3-dev", ver: "2.3.3-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby2.3-doc", ver: "2.3.3-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby2.3-tcltk", ver: "2.3.3-1+deb9u1", rls: "DEB9" ) ) != NULL){
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

