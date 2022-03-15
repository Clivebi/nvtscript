if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843454" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-21 08:47:28 +0100 (Wed, 21 Feb 2018)" );
	script_cve_id( "CVE-2016-5008", "CVE-2017-1000256", "CVE-2018-5748", "CVE-2018-6764" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-16 20:21:00 +0000 (Mon, 16 Nov 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libvirt USN-3576-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Vivian Zhang and Christoph Anton Mitterer
  discovered that libvirt incorrectly disabled password authentication when the
  VNC password was set to an empty string. A remote attacker could possibly use
  this issue to bypass authentication, contrary to expectations. This issue only
  affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-5008) Daniel P.
  Berrange discovered that libvirt incorrectly handled validating SSL/TLS
  certificates. A remote attacker could possibly use this issue to obtain
  sensitive information. This issue only affected Ubuntu 17.10. (CVE-2017-1000256)
  Daniel P. Berrange and Peter Krempa discovered that libvirt incorrectly handled
  large QEMU replies. An attacker could possibly use this issue to cause libvirt
  to crash, resulting in a denial of service. (CVE-2018-5748) Pedro Sampaio
  discovered that libvirt incorrectly handled the libnss_dns.so module. An
  attacker in a libvirt_lxc session could possibly use this issue to execute
  arbitrary code. This issue only affected Ubuntu 16.04 LTS and Ubuntu 17.10.
  (CVE-2018-6764)" );
	script_tag( name: "affected", value: "libvirt on Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3576-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3576-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|16\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libvirt-bin", ver: "1.2.2-0ubuntu13.1.26", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libvirt0", ver: "1.2.2-0ubuntu13.1.26", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "libvirt-bin", ver: "3.6.0-1ubuntu6.3", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libvirt0", ver: "3.6.0-1ubuntu6.3", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libvirt-bin", ver: "1.3.1-1ubuntu10.19", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libvirt0", ver: "1.3.1-1ubuntu10.19", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

