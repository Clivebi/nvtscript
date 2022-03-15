if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844973" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2021-24489", "CVE-2017-5715", "CVE-2020-24511", "CVE-2020-24512", "CVE-2020-24513" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-30 20:54:00 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-10 03:00:37 +0000 (Thu, 10 Jun 2021)" );
	script_name( "Ubuntu: Security Advisory for intel-microcode (USN-4985-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4985-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-June/006065.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'intel-microcode'
  package(s) announced via the USN-4985-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that some Intel processors may not properly invalidate
cache entries used by Intel Virtualization Technology for Directed I/O
(VT-d). This may allow a local user to perform a privilege escalation
attack. (CVE-2021-24489)

Joseph Nuzman discovered that some Intel processors may not properly apply
EIBRS mitigations (originally developed for CVE-2017-5715) and hence may
allow unauthorized memory reads via sidechannel attacks. A local attacker
could use this to expose sensitive information, including kernel
memory. (CVE-2020-24511)

Travis Downs discovered that some Intel processors did not properly flush
cache-lines for trivial-data values. This may allow an unauthorized user to
infer the presence of these trivial-data-cache-lines via timing sidechannel
attacks. A local attacker could use this to expose sensitive
information. (CVE-2020-24512)

It was discovered that certain Intel Atom processors could expose memory
contents stored in microarchitectural buffers. A local attacker could use
this to expose sensitive information. (CVE-2020-24513)" );
	script_tag( name: "affected", value: "'intel-microcode' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "intel-microcode", ver: "3.20210608.0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "intel-microcode", ver: "3.20210608.0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "intel-microcode", ver: "3.20210608.0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
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

