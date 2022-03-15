if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704676" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2019-17361", "CVE-2020-11651", "CVE-2020-11652" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-20 01:17:00 +0000 (Thu, 20 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-05-07 03:00:32 +0000 (Thu, 07 May 2020)" );
	script_name( "Debian: Security Advisory for salt (DSA-4676-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|10)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4676.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4676-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'salt'
  package(s) announced via the DSA-4676-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in salt, a powerful remote
execution manager, which could result in retrieve of user tokens from
the salt master, execution of arbitrary commands on salt minions,
arbitrary directory access to authenticated users or arbitrary code
execution on salt-api hosts." );
	script_tag( name: "affected", value: "'salt' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), these problems have been fixed
in version 2016.11.2+ds-1+deb9u3.

For the stable distribution (buster), these problems have been fixed in
version 2018.3.4+dfsg1-6+deb10u1.

We recommend that you upgrade your salt packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "salt-api", ver: "2016.11.2+ds-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-cloud", ver: "2016.11.2+ds-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-common", ver: "2016.11.2+ds-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-doc", ver: "2016.11.2+ds-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-master", ver: "2016.11.2+ds-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-minion", ver: "2016.11.2+ds-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-proxy", ver: "2016.11.2+ds-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-ssh", ver: "2016.11.2+ds-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-syndic", ver: "2016.11.2+ds-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-api", ver: "2018.3.4+dfsg1-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-cloud", ver: "2018.3.4+dfsg1-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-common", ver: "2018.3.4+dfsg1-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-doc", ver: "2018.3.4+dfsg1-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-master", ver: "2018.3.4+dfsg1-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-minion", ver: "2018.3.4+dfsg1-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-proxy", ver: "2018.3.4+dfsg1-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-ssh", ver: "2018.3.4+dfsg1-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "salt-syndic", ver: "2018.3.4+dfsg1-6+deb10u1", rls: "DEB10" ) )){
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

