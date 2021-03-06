if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703035" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-6271", "CVE-2014-7169" );
	script_name( "Debian Security Advisory DSA 3035-1 (bash - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-10-01 17:00:22 +0530 (Wed, 01 Oct 2014)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3035.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "bash on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 4.2+dfsg-0.1+deb7u3.

We recommend that you upgrade your bash packages." );
	script_tag( name: "summary", value: "Tavis Ormandy discovered that the patch applied to fix CVE-2014-6271 released in DSA-3032-1 for bash, the GNU Bourne-Again Shell, was
incomplete and could still allow some characters to be injected into
another environment (CVE-2014-7169
). With this update prefix and suffix
for environment variable names which contain shell functions are added
as hardening measure.

Additionally two out-of-bounds array accesses in the bash parser are
fixed which were revealed in Red Hat's internal analysis for these
issues and also independently reported by Todd Sabin." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "bash", ver: "4.2+dfsg-0.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bash-builtins", ver: "4.2+dfsg-0.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bash-doc", ver: "4.2+dfsg-0.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bash-static", ver: "4.2+dfsg-0.1+deb7u3", rls: "DEB7" ) ) != NULL){
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

