if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703960" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_cve_id( "CVE-2017-7526" );
	script_name( "Debian Security Advisory DSA 3960-1 (gnupg - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-01 00:00:00 +0200 (Fri, 01 Sep 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3960.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "gnupg on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1.4.18-7+deb8u4.

We recommend that you upgrade your gnupg packages." );
	script_tag( name: "summary", value: "Daniel J. Bernstein, Joachim Breitner, Daniel Genkin, Leon Groot
Bruinderink, Nadia Heninger, Tanja Lange, Christine van Vredendaal and
Yuval Yarom discovered that GnuPG is prone to a local side-channel
attack allowing full key recovery for RSA-1024." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gnupg", ver: "1.4.18-7+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnupg-curl", ver: "1.4.18-7+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gpgv", ver: "1.4.18-7+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gpgv-win32", ver: "1.4.18-7+deb8u4", rls: "DEB8" ) ) != NULL){
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

