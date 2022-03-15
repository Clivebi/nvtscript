if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702787" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-6172" );
	script_name( "Debian Security Advisory DSA 2787-1 (roundcube - design error)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-10-27 00:00:00 +0200 (Sun, 27 Oct 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2787.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "roundcube on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 0.7.2-9+deb7u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your roundcube packages." );
	script_tag( name: "summary", value: "It was discovered that roundcube, a skinnable AJAX based webmail
solution for IMAP servers, does not properly sanitize the _session
parameter in steps/utils/save_pref.inc during saving preferences. The
vulnerability can be exploited to overwrite configuration settings and
subsequently allowing random file access, manipulated SQL queries and
even code execution.

roundcube in the oldstable distribution (squeeze) is not affected by
this problem." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "roundcube", ver: "0.7.2-9+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-core", ver: "0.7.2-9+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-mysql", ver: "0.7.2-9+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-pgsql", ver: "0.7.2-9+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-plugins", ver: "0.7.2-9+deb7u1", rls: "DEB7" ) ) != NULL){
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

