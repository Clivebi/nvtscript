if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704332" );
	script_version( "2021-06-21T12:14:05+0000" );
	script_cve_id( "CVE-2018-16395", "CVE-2018-16396" );
	script_name( "Debian Security Advisory DSA 4332-1 (ruby2.3 - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 12:14:05 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-03 00:00:00 +0100 (Sat, 03 Nov 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4332.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "ruby2.3 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 2.3.3-1+deb9u4.

We recommend that you upgrade your ruby2.3 packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/ruby2.3" );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the interpreter for the
Ruby language. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2018-16395
Tyler Eckstein reported that the equality check of
OpenSSL::X509::Name could return true for non-equal objects. If a
malicious X.509 certificate is passed to compare with an existing
certificate, there is a possibility to be judged incorrectly that
they are equal.

CVE-2018-16396
Chris Seaton discovered that tainted flags are not propagated in
Array#pack and String#unpack with some directives." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libruby2.3", ver: "2.3.3-1+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.3", ver: "2.3.3-1+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.3-dev", ver: "2.3.3-1+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.3-doc", ver: "2.3.3-1+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.3-tcltk", ver: "2.3.3-1+deb9u4", rls: "DEB9" ) )){
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

