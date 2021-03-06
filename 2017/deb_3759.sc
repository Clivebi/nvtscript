if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703759" );
	script_version( "2021-09-10T14:01:42+0000" );
	script_cve_id( "CVE-2016-10127" );
	script_name( "Debian Security Advisory DSA 3759-1 (python-pysaml2 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-10 14:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-12 00:00:00 +0100 (Thu, 12 Jan 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-03-08 01:07:00 +0000 (Wed, 08 Mar 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3759.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "python-pysaml2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 2.0.0-1+deb8u1.

For the testing (stretch) and unstable (sid) distributions, this
problem has been fixed in version 3.0.0-5.

We recommend that you upgrade your python-pysaml2 packages." );
	script_tag( name: "summary", value: "Matias P. Brutti discovered that
python-pysaml2, a Python implementation of the Security Assertion Markup Language
2.0, did not correctly sanitize the XML messages it handled. This allowed a remote
attacker to perform XML External Entity attacks, leading to a wide
range of exploits." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-pysaml2", ver: "3.0.0-5", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pysaml2-doc", ver: "3.0.0-5", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pysaml2", ver: "3.0.0-5", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pysaml2", ver: "2.0.0-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pysaml2-doc", ver: "2.0.0-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

