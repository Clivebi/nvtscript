if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892544" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2020-36221", "CVE-2020-36222", "CVE-2020-36223", "CVE-2020-36224", "CVE-2020-36225", "CVE-2020-36226", "CVE-2020-36227", "CVE-2020-36228", "CVE-2020-36229", "CVE-2020-36230" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-02-04 04:00:12 +0000 (Thu, 04 Feb 2021)" );
	script_name( "Debian LTS: Security Advisory for openldap (DLA-2544-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2544-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2544-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openldap'
  package(s) announced via the DLA-2544-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in OpenLDAP, a free
implementation of the Lightweight Directory Access Protocol. An
unauthenticated remote attacker can take advantage of these flaws to
cause a denial of service (slapd daemon crash, infinite loops) via
specially crafted packets." );
	script_tag( name: "affected", value: "'openldap' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
2.4.44+dfsg-5+deb9u7.

We recommend that you upgrade your openldap packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ldap-utils", ver: "2.4.44+dfsg-5+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libldap-2.4-2", ver: "2.4.44+dfsg-5+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libldap-2.4-2-dbg", ver: "2.4.44+dfsg-5+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libldap-common", ver: "2.4.44+dfsg-5+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libldap2-dev", ver: "2.4.44+dfsg-5+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slapd", ver: "2.4.44+dfsg-5+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slapd-dbg", ver: "2.4.44+dfsg-5+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slapd-smbk5pwd", ver: "2.4.44+dfsg-5+deb9u7", rls: "DEB9" ) )){
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

