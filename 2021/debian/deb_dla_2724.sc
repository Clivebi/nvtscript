if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892724" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2019-18823" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-22 13:29:00 +0000 (Fri, 22 May 2020)" );
	script_tag( name: "creation_date", value: "2021-08-02 03:00:13 +0000 (Mon, 02 Aug 2021)" );
	script_name( "Debian LTS: Security Advisory for condor (DLA-2724-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/08/msg00000.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2724-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2724-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/963777" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'condor'
  package(s) announced via the DLA-2724-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "HTCondor, a distributed workload management system, has Incorrect Access
Control. It is possible to use a different authentication method to submit a
job than the administrator has specified. If the administrator has configured
the READ or WRITE methods to include CLAIMTOBE, then it is possible to
impersonate another user to the condor_schedd, for example to submit or remove
jobs." );
	script_tag( name: "affected", value: "'condor' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
8.4.11~dfsg.1-1+deb9u1.

We recommend that you upgrade your condor packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "condor", ver: "8.4.11~dfsg.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "condor-dbg", ver: "8.4.11~dfsg.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "condor-dev", ver: "8.4.11~dfsg.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "condor-doc", ver: "8.4.11~dfsg.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "htcondor", ver: "8.4.11~dfsg.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "htcondor-dbg", ver: "8.4.11~dfsg.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "htcondor-dev", ver: "8.4.11~dfsg.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "htcondor-doc", ver: "8.4.11~dfsg.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libclassad-dev", ver: "8.4.11~dfsg.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libclassad7", ver: "8.4.11~dfsg.1-1+deb9u1", rls: "DEB9" ) )){
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

