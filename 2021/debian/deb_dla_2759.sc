if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892759" );
	script_version( "2021-09-18T01:00:07+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-18 01:00:07 +0000 (Sat, 18 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-18 01:00:07 +0000 (Sat, 18 Sep 2021)" );
	script_name( "Debian LTS: Security Advisory for gnutls28 (DLA-2759-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/09/msg00007.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2759-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2759-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/961889" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls28'
  package(s) announced via the DLA-2759-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "GnuTLS, a portable cryptography library, fails to validate alternate
trust chains in some conditions. In particular this breaks connecting
to servers that use Let's Encrypt certificates, starting 2021-10-01." );
	script_tag( name: "affected", value: "'gnutls28' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
3.5.8-5+deb9u6.

We recommend that you upgrade your gnutls28 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gnutls-bin", ver: "3.5.8-5+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gnutls-doc", ver: "3.5.8-5+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgnutls-dane0", ver: "3.5.8-5+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgnutls-openssl27", ver: "3.5.8-5+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgnutls28-dev", ver: "3.5.8-5+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgnutls30", ver: "3.5.8-5+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgnutlsxx28", ver: "3.5.8-5+deb9u6", rls: "DEB9" ) )){
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

