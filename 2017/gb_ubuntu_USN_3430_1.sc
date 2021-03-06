if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843319" );
	script_version( "2021-09-09T12:15:00+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 12:15:00 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-05 11:54:50 +0530 (Thu, 05 Oct 2017)" );
	script_cve_id( "CVE-2017-14491", "CVE-2017-14492", "CVE-2017-14493", "CVE-2017-14494", "CVE-2017-14495", "CVE-2017-14496" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-11 01:29:00 +0000 (Fri, 11 May 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for dnsmasq USN-3430-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dnsmasq'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Felix Wilhelm, Fermin J. Serna, Gabriel
  Campana and Kevin Hamacher discovered that Dnsmasq incorrectly handled DNS
  requests. A remote attacker could use this issue to cause Dnsmasq to crash,
  resulting in a denial of service, or possibly execute arbitrary code.
  (CVE-2017-14491) Felix Wilhelm, Fermin J. Serna, Gabriel Campana and Kevin
  Hamacher discovered that Dnsmasq incorrectly handled IPv6 router advertisements.
  A remote attacker could use this issue to cause Dnsmasq to crash, resulting in a
  denial of service, or possibly execute arbitrary code. (CVE-2017-14492) Felix
  Wilhelm, Fermin J. Serna, Gabriel Campana and Kevin Hamacher discovered that
  Dnsmasq incorrectly handled DHCPv6 requests. A remote attacker could use this
  issue to cause Dnsmasq to crash, resulting in a denial of service, or possibly
  execute arbitrary code. (CVE-2017-14493) Felix Wilhelm, Fermin J. Serna, Gabriel
  Campana and Kevin Hamacher discovered that Dnsmasq incorrectly handled DHCPv6
  packets. A remote attacker could use this issue to possibly obtain sensitive
  memory contents. (CVE-2017-14494) Felix Wilhelm, Fermin J. Serna, Gabriel
  Campana and Kevin Hamacher discovered that Dnsmasq incorrectly handled DNS
  requests. A remote attacker could use this issue to cause Dnsmasq to consume
  memory, resulting in a denial of service. (CVE-2017-14495) Felix Wilhelm, Fermin
  J. Serna, Gabriel Campana and Kevin Hamacher discovered that Dnsmasq incorrectly
  handled DNS requests. A remote attacker could use this issue to cause Dnsmasq to
  crash, resulting in a denial of service. (CVE-2017-14496)" );
	script_tag( name: "affected", value: "dnsmasq on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3430-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3430-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "dnsmasq", ver: "2.68-1ubuntu0.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dnsmasq-base", ver: "2.68-1ubuntu0.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dnsmasq-utils", ver: "2.68-1ubuntu0.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "dnsmasq", ver: "2.76-5ubuntu0.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dnsmasq-base", ver: "2.76-5ubuntu0.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dnsmasq-utils", ver: "2.76-5ubuntu0.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "dnsmasq", ver: "2.75-1ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dnsmasq-base", ver: "2.75-1ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dnsmasq-utils", ver: "2.75-1ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

