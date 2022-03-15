if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843098" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-21 05:50:50 +0100 (Tue, 21 Mar 2017)" );
	script_cve_id( "CVE-2016-8610", "CVE-2016-7444", "CVE-2017-5334", "CVE-2017-5335", "CVE-2017-5336", "CVE-2017-5337" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for gnutls26 USN-3183-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls26'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3183-1 fixed CVE-2016-8610 in GnuTLS in
  Ubuntu 16.04 LTS and Ubuntu 16.10. This update provides the corresponding update
  for Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. Original advisory details: Stefan
  Buehler discovered that GnuTLS incorrectly verified the serial length of OCSP
  responses. A remote attacker could possibly use this issue to bypass certain
  certificate validation measures. This issue only applied to Ubuntu 16.04 LTS.
  (CVE-2016-7444) Shi Lei discovered that GnuTLS incorrectly handled certain
  warning alerts. A remote attacker could possibly use this issue to cause GnuTLS
  to hang, resulting in a denial of service. This issue has only been addressed in
  Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-8610) It was discovered that GnuTLS
  incorrectly decoded X.509 certificates with a Proxy Certificate Information
  extension. A remote attacker could use this issue to cause GnuTLS to crash,
  resulting in a denial of service, or possibly execute arbitrary code. This issue
  only affected Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2017-5334) It was
  discovered that GnuTLS incorrectly handled certain OpenPGP certificates. A
  remote attacker could possibly use this issue to cause GnuTLS to crash,
  resulting in a denial of service, or possibly execute arbitrary code.
  (CVE-2017-5335, CVE-2017-5336, CVE-2017-5337)" );
	script_tag( name: "affected", value: "gnutls26 on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3183-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3183-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libgnutls26:i386", ver: "2.12.23-12ubuntu2.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgnutls26:amd64", ver: "2.12.23-12ubuntu2.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libgnutls26:i386", ver: "2.12.14-5ubuntu3.14", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgnutls26:amd64", ver: "2.12.14-5ubuntu3.14", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

