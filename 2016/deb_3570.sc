if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703570" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-3105" );
	script_name( "Debian Security Advisory DSA 3570-1 (mercurial - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-05-05 00:00:00 +0200 (Thu, 05 May 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3570.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "mercurial on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 3.1.2-2+deb8u3.

For the unstable distribution (sid), this problem has been fixed in
version 3.8.1-1.

We recommend that you upgrade your mercurial packages." );
	script_tag( name: "summary", value: "Blake Burkhart discovered an arbitrary
code execution flaw in Mercurial, a distributed version control system, when
using the convert extension on Git repositories with specially crafted names.
This flaw in particular affects automated code conversion services that allow
arbitrary repository names." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "mercurial", ver: "3.1.2-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mercurial-common", ver: "3.1.2-2+deb8u3", rls: "DEB8" ) ) != NULL){
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

