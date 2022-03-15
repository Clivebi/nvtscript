if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843225" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-23 07:17:19 +0200 (Fri, 23 Jun 2017)" );
	script_cve_id( "CVE-2016-6329", "CVE-2017-7479", "CVE-2017-7508", "CVE-2017-7512", "CVE-2017-7520", "CVE-2017-7521" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openvpn USN-3339-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openvpn'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Karthikeyan Bhargavan and Ga&#235 tan
  Leurent discovered that 64-bit block ciphers are vulnerable to a birthday
  attack. A remote attacker could possibly use this issue to recover cleartext
  data. Fixing this issue requires a configuration change to switch to a different
  cipher. This update adds a warning to the log file when a 64-bit block cipher is
  in use. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu
  16.10. (CVE-2016-6329) It was discovered that OpenVPN incorrectly handled
  rollover of packet ids. An authenticated remote attacker could use this issue to
  cause OpenVPN to crash, resulting in a denial of service. This issue only
  affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2017-7479)
  Guido Vranken discovered that OpenVPN incorrectly handled certain malformed IPv6
  packets. A remote attacker could use this issue to cause OpenVPN to crash,
  resulting in a denial of service. (CVE-2017-7508) Guido Vranken discovered that
  OpenVPN incorrectly handled memory. A remote attacker could use this issue to
  cause OpenVPN to crash, resulting in a denial of service. (CVE-2017-7512) Guido
  Vranken discovered that OpenVPN incorrectly handled an HTTP proxy with NTLM
  authentication. A remote attacker could use this issue to cause OpenVPN clients
  to crash, resulting in a denial of service, or possibly expose sensitive memory
  contents. (CVE-2017-7520) Guido Vranken discovered that OpenVPN incorrectly
  handled certain x509 extensions. A remote attacker could use this issue to cause
  OpenVPN to crash, resulting in a denial of service. (CVE-2017-7521)" );
	script_tag( name: "affected", value: "openvpn on Ubuntu 17.04,
  Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3339-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3339-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.10|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "openvpn", ver: "2.3.2-7ubuntu3.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "openvpn", ver: "2.4.0-4ubuntu1.3", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "openvpn", ver: "2.3.11-1ubuntu2.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "openvpn", ver: "2.3.10-1ubuntu2.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

