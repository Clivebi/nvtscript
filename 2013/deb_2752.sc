if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702752" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-5724" );
	script_name( "Debian Security Advisory DSA 2752-1 (phpbb3 - permissions too wide)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-07 00:00:00 +0200 (Sat, 07 Sep 2013)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2752.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "phpbb3 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 3.0.7-PL1-4+squeeze1.

For the stable distribution (wheezy), this problem has been fixed in
version 3.0.10-4+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 3.0.11-4.

We recommend that you upgrade your phpbb3 packages." );
	script_tag( name: "summary", value: "Andreas Beckmann discovered that phpBB, a web forum, as installed in
Debian, sets incorrect permissions for cached files, allowing a
malicious local user to overwrite them." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "phpbb3", ver: "3.0.7-PL1-4+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "phpbb3-l10n", ver: "3.0.7-PL1-4+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "phpbb3", ver: "3.0.10-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "phpbb3-l10n", ver: "3.0.10-4+deb7u1", rls: "DEB7" ) ) != NULL){
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

