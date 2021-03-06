if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704265" );
	script_version( "2019-07-04T09:25:28+0000" );
	script_name( "Debian Security Advisory DSA 4265-1 (xml-security-c - security update)" );
	script_tag( name: "last_modification", value: "2019-07-04 09:25:28 +0000 (Thu, 04 Jul 2019)" );
	script_tag( name: "creation_date", value: "2018-08-05 00:00:00 +0200 (Sun, 05 Aug 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4265.html" );
	script_xref( name: "URL", value: "https://shibboleth.net/community/advisories/secadv_20180803.txt" );
	script_xref( name: "URL", value: "https://issues.apache.org/jira/projects/SANTUARIO/issues/SANTUARIO-491" );
	script_xref( name: "URL", value: "https://bugs.debian.org/905332" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "xml-security-c on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1.7.3-4+deb9u1.

We recommend that you upgrade your xml-security-c packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/xml-security-c" );
	script_tag( name: "summary", value: "It was discovered that the Apache XML Security for C++ library performed
insufficient validation of KeyInfo hints, which could result in denial
of service via NULL pointer dereferences when processing malformed XML
data." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxml-security-c-dev", ver: "1.7.3-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml-security-c17v5", ver: "1.7.3-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xml-security-c-utils", ver: "1.7.3-4+deb9u1", rls: "DEB9" ) )){
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

