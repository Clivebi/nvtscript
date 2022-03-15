if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703226" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2012-1836", "CVE-2012-6696", "CVE-2012-6697", "CVE-2015-6674" );
	script_name( "Debian Security Advisory DSA 3226-1 (inspircd - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-15 00:00:00 +0200 (Wed, 15 Apr 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3226.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "inspircd on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 2.0.5-1+deb7u1.

For the upcoming stable distribution (jessie) and unstable
distribution (sid), this problem has been fixed in version 2.0.16-1.

We recommend that you upgrade your inspircd packages." );
	script_tag( name: "summary", value: "Adam discovered several problems in inspircd, an IRC daemon:

An incomplete patch for CVE-2012-1836

failed to adequately resolve the problem where maliciously crafted DNS
requests could lead to remote code execution through a heap-based buffer
overflow.

The incorrect processing of specific DNS packets could trigger an
infinite loop, thus resulting in a denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "inspircd", ver: "2.0.5-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inspircd-dbg", ver: "2.0.5-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inspircd", ver: "2.0.16-1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inspircd-dbg", ver: "2.0.16-1", rls: "DEB8" ) ) != NULL){
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

