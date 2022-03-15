if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844805" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2020-10736", "CVE-2020-10753", "CVE-2018-1128", "CVE-2020-25660" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-28 19:43:00 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2021-01-29 04:00:32 +0000 (Fri, 29 Jan 2021)" );
	script_name( "Ubuntu: Security Advisory for ceph (USN-4706-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4706-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-January/005863.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ceph'
  package(s) announced via the USN-4706-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Olle Segerdahl found that ceph-mon and ceph-mgr daemons did not properly
restrict access, resulting in gaining access to unauthorized resources. An
authenticated user could use this vulnerability to modify the configuration and
possibly conduct further attacks. (CVE-2020-10736)

Adam Mohammed found that Ceph Object Gateway was vulnerable to HTTP header
injection via a CORS ExposeHeader tag. An attacker could use this to gain access
or cause a crash. (CVE-2020-10753)

Ilya Dryomov found that Cephx authentication did not verify Ceph clients
correctly and was then vulnerable to replay attacks in Nautilus. An attacker
could use the Ceph cluster network to authenticate via a packet sniffer and
perform actions. This issue is a reintroduction of CVE-2018-1128.
(CVE-2020-25660)" );
	script_tag( name: "affected", value: "'ceph' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "ceph", ver: "15.2.7-0ubuntu0.20.04.2", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ceph-base", ver: "15.2.7-0ubuntu0.20.04.2", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ceph-common", ver: "15.2.7-0ubuntu0.20.04.2", rls: "UBUNTU20.04 LTS" ) )){
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
}
if(release == "UBUNTU20.10"){
	if(!isnull( res = isdpkgvuln( pkg: "ceph", ver: "15.2.7-0ubuntu0.20.10.3", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ceph-base", ver: "15.2.7-0ubuntu0.20.10.3", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ceph-common", ver: "15.2.7-0ubuntu0.20.10.3", rls: "UBUNTU20.10" ) )){
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
}
exit( 0 );

