if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892773" );
	script_version( "2021-10-01T01:00:32+0000" );
	script_cve_id( "CVE-2021-22946", "CVE-2021-22947" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-10-01 01:00:32 +0000 (Fri, 01 Oct 2021)" );
	script_tag( name: "creation_date", value: "2021-10-01 01:00:32 +0000 (Fri, 01 Oct 2021)" );
	script_name( "Debian LTS: Security Advisory for curl (DLA-2773-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2773-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2773-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl'
  package(s) announced via the DLA-2773-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two issues have been found in curl, a command line tool and an easy-to-use
client-side library for transferring data with URL syntax.

CVE-2021-22946
Crafted answers from a server might force clients to not use TLS on
connections though TLS was required and expected.

CVE-2021-22947
When using STARTTLS to initiate a TLS connection, the server might
send multiple answers before the TLS upgrade and such the client
would handle them as being trusted. This could be used by a
MITM-attacker to inject fake response data." );
	script_tag( name: "affected", value: "'curl' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
7.52.1-5+deb9u16.

We recommend that you upgrade your curl packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "curl", ver: "7.52.1-5+deb9u16", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3", ver: "7.52.1-5+deb9u16", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-dbg", ver: "7.52.1-5+deb9u16", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.52.1-5+deb9u16", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.52.1-5+deb9u16", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-doc", ver: "7.52.1-5+deb9u16", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.52.1-5+deb9u16", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-nss-dev", ver: "7.52.1-5+deb9u16", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.52.1-5+deb9u16", rls: "DEB9" ) )){
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
exit( 0 );

