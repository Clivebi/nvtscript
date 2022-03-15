if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842740" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-10 05:21:23 +0200 (Tue, 10 May 2016)" );
	script_cve_id( "CVE-2015-8325", "CVE-2016-1907", "CVE-2016-1908", "CVE-2016-3115" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-11 10:29:00 +0000 (Tue, 11 Sep 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openssh USN-2966-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssh'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Shayan Sadigh discovered that OpenSSH
  incorrectly handled environment files when the UseLogin feature is enabled.
  A local attacker could use this issue to gain privileges. (CVE-2015-8325)

  Ben Hawkes discovered that OpenSSH incorrectly handled certain network
  traffic. A remote attacker could possibly use this issue to cause OpenSSH
  to crash, resulting in a denial of service. This issue only applied to
  Ubuntu 15.10. (CVE-2016-1907)

  Thomas Hoger discovered that OpenSSH incorrectly handled untrusted X11
  forwarding when the SECURITY extension is disabled. A connection configured
  as being untrusted could get switched to trusted in certain scenarios,
  contrary to expectations. (CVE-2016-1908)

  It was discovered that OpenSSH incorrectly handled certain X11 forwarding
  data. A remote authenticated attacker could possibly use this issue to
  bypass certain intended command restrictions. (CVE-2016-3115)" );
	script_tag( name: "affected", value: "openssh on Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2966-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2966-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|15\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "openssh-server", ver: "1:6.6p1-2ubuntu2.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "openssh-server", ver: "1:5.9p1-5ubuntu1.9", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "openssh-server", ver: "1:6.9p1-2ubuntu0.2", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

