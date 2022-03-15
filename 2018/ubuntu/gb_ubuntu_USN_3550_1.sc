if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843438" );
	script_version( "2021-06-04T11:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-04 11:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-31 07:55:06 +0100 (Wed, 31 Jan 2018)" );
	script_cve_id( "CVE-2017-12374", "CVE-2017-12375", "CVE-2017-12379", "CVE-2017-12380", "CVE-2017-12376", "CVE-2017-12377", "CVE-2017-12378" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-16 01:29:00 +0000 (Fri, 16 Mar 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for clamav USN-3550-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clamav'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that ClamAV incorrectly
  handled parsing certain mail messages. A remote attacker could use this issue to
  cause ClamAV to crash, resulting in a denial of service, or possibly execute
  arbitrary code. (CVE-2017-12374, CVE-2017-12375, CVE-2017-12379, CVE-2017-12380)
  It was discovered that ClamAV incorrectly handled parsing certain PDF files. A
  remote attacker could use this issue to cause ClamAV to crash, resulting in a
  denial of service, or possibly execute arbitrary code. (CVE-2017-12376) It was
  discovered that ClamAV incorrectly handled parsing certain mew packet files. A
  remote attacker could use this issue to cause ClamAV to crash, resulting in a
  denial of service, or possibly execute arbitrary code. (CVE-2017-12377) It was
  discovered that ClamAV incorrectly handled parsing certain TAR files. A remote
  attacker could possibly use this issue to cause ClamAV to crash, resulting in a
  denial of service. (CVE-2017-12378) In the default installation, attackers would
  be isolated by the ClamAV AppArmor profile." );
	script_tag( name: "affected", value: "clamav on Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3550-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3550-1/" );
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
	if(( res = isdpkgvuln( pkg: "clamav", ver: "0.99.3+addedllvm-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "clamav", ver: "0.99.3+addedllvm-0ubuntu0.17.10.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "clamav", ver: "0.99.3+addedllvm-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

