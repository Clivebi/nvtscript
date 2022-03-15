if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891779" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-3883" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-13 16:15:00 +0000 (Fri, 13 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:00:12 +0000 (Tue, 07 May 2019)" );
	script_name( "Debian LTS: Security Advisory for 389-ds-base (DLA-1779-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00008.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1779-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/927939" );
	script_tag( name: "summary", value: "The remote host is missing an update for the '389-ds-base'
  package(s) announced via the DLA-1779-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In 389-ds-base up to version 1.4.1.2, requests were handled by worker
threads. Each socket had been waited for by the worker for at most
'ioblocktimeout' seconds. However, this timeout applied only to
un-encrypted requests. Connections using SSL/TLS were not taking this
timeout into account during reads, and may have hung longer. An
unauthenticated attacker could have repeatedly created hanging LDAP
requests to hang all the workers, resulting in a Denial of Service." );
	script_tag( name: "affected", value: "'389-ds-base' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.3.3.5-4+deb8u6.

We recommend that you upgrade your 389-ds-base packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "389-ds", ver: "1.3.3.5-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "389-ds-base", ver: "1.3.3.5-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "389-ds-base-dbg", ver: "1.3.3.5-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "389-ds-base-dev", ver: "1.3.3.5-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "389-ds-base-libs", ver: "1.3.3.5-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "389-ds-base-libs-dbg", ver: "1.3.3.5-4+deb8u6", rls: "DEB8" ) )){
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

