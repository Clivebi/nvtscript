if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844645" );
	script_version( "2021-07-09T02:00:48+0000" );
	script_cve_id( "CVE-2017-18367" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-09 02:00:48 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-14 22:15:00 +0000 (Wed, 14 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-08 03:00:39 +0000 (Thu, 08 Oct 2020)" );
	script_name( "Ubuntu: Security Advisory for golang-github-seccomp-libseccomp-golang (USN-4574-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4574-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-October/005685.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'golang-github-seccomp-libseccomp-golang'
  package(s) announced via the USN-4574-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that libseccomp-golang did not properly generate BPFs. If
a process were running under a restrictive seccomp filter that specified
multiple syscall arguments, the application could potentially bypass the
intended restrictions put in place by seccomp." );
	script_tag( name: "affected", value: "'golang-github-seccomp-libseccomp-golang' package(s) on Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "golang-github-seccomp-libseccomp-golang-dev", ver: "0.0~git20150813.0.1b506fc-2+deb9u1build0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
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

