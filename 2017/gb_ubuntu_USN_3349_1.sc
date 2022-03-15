if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843238" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-14 15:54:52 +0530 (Fri, 14 Jul 2017)" );
	script_cve_id( "CVE-2016-2519", "CVE-2016-7426", "CVE-2016-7427", "CVE-2016-7428", "CVE-2016-7429", "CVE-2016-7431", "CVE-2016-7433", "CVE-2016-7434", "CVE-2016-9042", "CVE-2016-9310", "CVE-2016-9311", "CVE-2017-6458", "CVE-2017-6460", "CVE-2017-6462", "CVE-2017-6463", "CVE-2017-6464" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-24 11:29:00 +0000 (Thu, 24 Jan 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for ntp USN-3349-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Yihan Lian discovered that NTP incorrectly
  handled certain large request data values. A remote attacker could possibly use
  this issue to cause NTP to crash, resulting in a denial of service. This issue
  only affected Ubuntu 16.04 LTS. (CVE-2016-2519) Miroslav Lichvar discovered that
  NTP incorrectly handled certain spoofed addresses when performing rate limiting.
  A remote attacker could possibly use this issue to perform a denial of service.
  This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, and Ubuntu 16.10.
  (CVE-2016-7426) Matthew Van Gundy discovered that NTP incorrectly handled
  certain crafted broadcast mode packets. A remote attacker could possibly use
  this issue to perform a denial of service. This issue only affected Ubuntu 14.04
  LTS, Ubuntu 16.04 LTS, and Ubuntu 16.10. (CVE-2016-7427, CVE-2016-7428) Miroslav
  Lichvar discovered that NTP incorrectly handled certain responses. A remote
  attacker could possibly use this issue to perform a denial of service. This
  issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, and Ubuntu 16.10.
  (CVE-2016-7429) Sharon Goldberg and Aanchal Malhotra discovered that NTP
  incorrectly handled origin timestamps of zero. A remote attacker could possibly
  use this issue to bypass the origin timestamp protection mechanism. This issue
  only affected Ubuntu 16.10. (CVE-2016-7431) Brian Utterback, Sharon Goldberg and
  Aanchal Malhotra discovered that NTP incorrectly performed initial sync
  calculations. This issue only applied to Ubuntu 16.04 LTS and Ubuntu 16.10.
  (CVE-2016-7433) Magnus Stubman discovered that NTP incorrectly handled certain
  mrulist queries. A remote attacker could possibly use this issue to cause NTP to
  crash, resulting in a denial of service. This issue only affected Ubuntu 16.04
  LTS and Ubuntu 16.10. (CVE-2016-7434) Matthew Van Gund discovered that NTP
  incorrectly handled origin timestamp checks. A remote attacker could possibly
  use this issue to perform a denial of service. This issue only affected Ubuntu
  Ubuntu 16.10, and Ubuntu 17.04. (CVE-2016-9042) Matthew Van Gundy discovered
  that NTP incorrectly handled certain control mode packets. A remote attacker
  could use this issue to set or unset traps. This issue only applied to Ubuntu
  14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-9310) Matthew Van Gundy
  discovered that NTP incorrectly handled the trap service. A remote attacker
  could possibly use this issue to cause NTP to crash, resulting in a denial of
  service. This issue only applied to Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and
  Ubuntu 16.10. (CVE-2016-9311) It was di ... Description truncated, for more
  information please check the Reference URL" );
	script_tag( name: "affected", value: "ntp on Ubuntu 17.04,
  Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3349-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3349-1/" );
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
	if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.6.p5+dfsg-3ubuntu2.14.04.11", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.8p9+dfsg-2ubuntu1.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.8p8+dfsg-1ubuntu2.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.8p4+dfsg-3ubuntu5.5", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

