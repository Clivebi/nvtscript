if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844714" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2020-7039", "CVE-2020-8608" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-14 03:50:00 +0000 (Sun, 14 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-11-13 04:00:32 +0000 (Fri, 13 Nov 2020)" );
	script_name( "Ubuntu: Security Advisory for slirp (USN-4632-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4632-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-November/005760.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'slirp'
  package(s) announced via the USN-4632-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the SLiRP networking implementation of the QEMU
emulator did not properly manage memory under certain circumstances. An
attacker could use this to cause a heap-based buffer overflow or other out-
of-bounds access, which can lead to a denial of service (application crash)
or potentially execute arbitrary code. (CVE-2020-7039)

It was discovered that the SLiRP networking implementation of the QEMU
emulator misuses snprintf return values. An attacker could use this to
cause a denial of service (application crash) or potentially execute
arbitrary code. (CVE-2020-8608)" );
	script_tag( name: "affected", value: "'slirp' package(s) on Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "slirp", ver: "1:1.0.17-8ubuntu18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "slirp", ver: "1:1.0.17-8ubuntu16.04.1", rls: "UBUNTU16.04 LTS" ) )){
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

