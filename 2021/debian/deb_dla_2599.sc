if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892599" );
	script_version( "2021-03-19T07:30:12+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-19 07:30:12 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-19 04:00:07 +0000 (Fri, 19 Mar 2021)" );
	script_name( "Debian LTS: Security Advisory for shibboleth-sp2 (DLA-2599-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/03/msg00023.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2599-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2599-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/985405" );
	script_xref( name: "URL", value: "https://shibboleth.net/community/advisories/secadv_20210317.txt" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'shibboleth-sp2'
  package(s) announced via the DLA-2599-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Toni Huttunen discovered that the Shibboleth service provider's template
engine used to render error pages could be abused for phishing attacks.

For additional information please refer to the upstream advisory at [link moved to references]" );
	script_tag( name: "affected", value: "'shibboleth-sp2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
2.6.0+dfsg1-4+deb9u2.

We recommend that you upgrade your shibboleth-sp2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-shib2", ver: "2.6.0+dfsg1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libshibsp-dev", ver: "2.6.0+dfsg1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libshibsp-doc", ver: "2.6.0+dfsg1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libshibsp-plugins", ver: "2.6.0+dfsg1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libshibsp7", ver: "2.6.0+dfsg1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "shibboleth-sp2-common", ver: "2.6.0+dfsg1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "shibboleth-sp2-utils", ver: "2.6.0+dfsg1-4+deb9u2", rls: "DEB9" ) )){
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

