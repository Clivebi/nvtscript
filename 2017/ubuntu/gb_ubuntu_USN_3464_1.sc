if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843351" );
	script_version( "2021-09-10T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 12:01:36 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-27 14:32:33 +0200 (Fri, 27 Oct 2017)" );
	script_cve_id( "CVE-2017-13089", "CVE-2017-13090", "CVE-2016-7098", "CVE-2017-6508" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-30 02:29:00 +0000 (Sat, 30 Dec 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for wget USN-3464-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wget'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Antti Levomki, Christian Jalio, and Joonas
  Pihlaja discovered that Wget incorrectly handled certain HTTP responses. A
  remote attacker could use this issue to cause Wget to crash, resulting in a
  denial of service, or possibly execute arbitrary code. (CVE-2017-13089,
  CVE-2017-13090) Dawid Golunski discovered that Wget incorrectly handled
  recursive or mirroring mode. A remote attacker could possibly use this issue to
  bypass intended access list restrictions. (CVE-2016-7098) Orange Tsai discovered
  that Wget incorrectly handled CRLF sequences in HTTP headers. A remote attacker
  could possibly use this issue to inject arbitrary HTTP headers.
  (CVE-2017-6508)" );
	script_tag( name: "affected", value: "wget on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3464-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3464-1/" );
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
	if(( res = isdpkgvuln( pkg: "wget", ver: "1.15-1ubuntu1.14.04.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "wget", ver: "1.18-2ubuntu1.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "wget", ver: "1.17.1-1ubuntu1.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

