if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703137" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2013-6892" );
	script_name( "Debian Security Advisory DSA 3137-1 (websvn - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-01-24 00:00:00 +0100 (Sat, 24 Jan 2015)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3137.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "websvn on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 2.3.3-1.1+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 2.3.3-1.2.

We recommend that you upgrade your websvn packages." );
	script_tag( name: "summary", value: "James Clawson discovered that websvn,
a web viewer for Subversion repositories, would follow symlinks in a repository
when presenting a file for download. An attacker with repository write access could
thereby access any file on disk readable by the user the webserver
runs as." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "websvn", ver: "2.3.3-1.1+deb7u1", rls: "DEB7" ) ) != NULL){
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

