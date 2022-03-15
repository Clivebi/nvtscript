if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843589" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-12 05:57:31 +0200 (Thu, 12 Jul 2018)" );
	script_cve_id( "CVE-2017-18248", "CVE-2018-4180", "CVE-2018-4181", "CVE-2018-6553" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for cups USN-3713-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cups'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that CUPS incorrectly handled certain print jobs with
invalid usernames. A remote attacker could possibly use this issue to cause
CUPS to crash, resulting in a denial of service. This issue only affected
Ubuntu 14.04 LTS, Ubuntu 17.10 and Ubuntu 18.04 LTS. (CVE-2017-18248)

Dan Bastone discovered that the CUPS dnssd backend incorrectly handled
certain environment variables. A local attacker could possibly use this
issue to escalate privileges. (CVE-2018-4180)

Eric Rafaloff and John Dunlap discovered that CUPS incorrectly handled
certain include directives. A local attacker could possibly use this issue
to read arbitrary files. (CVE-2018-4181)

Dan Bastone discovered that the CUPS AppArmor profile incorrectly confined
the dnssd backend. A local attacker could possibly use this issue to escape
confinement. (CVE-2018-6553)" );
	script_tag( name: "affected", value: "cups on Ubuntu 18.04 LTS,
  Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3713-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3713-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|18\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "cups", ver: "1.7.2-0ubuntu1.10", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "cups", ver: "2.2.4-7ubuntu3.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "cups", ver: "2.2.7-1ubuntu2.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "cups", ver: "2.1.3-4ubuntu0.5", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

