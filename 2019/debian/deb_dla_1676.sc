if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891676" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2017-15105" );
	script_name( "Debian LTS: Security Advisory for unbound (DLA-1676-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-15 00:00:00 +0100 (Fri, 15 Feb 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:24:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://unbound.net/downloads/CVE-2017-15105.txt" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00022.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "unbound on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.4.22-3+deb8u4.

We recommend that you upgrade your unbound packages." );
	script_tag( name: "summary", value: "Ralph Dolmans and Karst Koymans found a flaw in the way unbound, a
validating, recursive, caching DNS resolver, validated
wildcard-synthesized NSEC records.

An improperly validated wildcard NSEC record could be used to prove the
non-existence (NXDOMAIN answer) of an existing wildcard record, or trick
unbound into accepting a NODATA proof.

For more information please refer to the linked upstream advisory." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libunbound-dev", ver: "1.4.22-3+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libunbound2", ver: "1.4.22-3+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-unbound", ver: "1.4.22-3+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "unbound", ver: "1.4.22-3+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "unbound-anchor", ver: "1.4.22-3+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "unbound-host", ver: "1.4.22-3+deb8u4", rls: "DEB8" ) )){
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

