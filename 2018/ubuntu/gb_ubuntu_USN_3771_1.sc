if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843640" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-26 08:19:29 +0200 (Wed, 26 Sep 2018)" );
	script_cve_id( "CVE-2018-10811", "CVE-2018-16151", "CVE-2018-16152", "CVE-2018-5388" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-18 14:28:00 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for strongswan USN-3771-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'strongswan'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "insight", value: "It was discovered that strongSwan incorrectly
handled IKEv2 key derivation. A remote attacker could possibly use this issue to
cause strongSwan to crash, resulting in a denial of service. (CVE-2018-10811)

Sze Yiu Chau discovered that strongSwan incorrectly handled parsing OIDs in
the gmp plugin. A remote attacker could possibly use this issue to bypass
authorization. (CVE-2018-16151)

Sze Yiu Chau discovered that strongSwan incorrectly handled certain
parameters fields in the gmp plugin. A remote attacker could possibly use
this issue to bypass authorization. (CVE-2018-16152)

It was discovered that strongSwan incorrectly handled the stroke plugin. A
local administrator could use this issue to cause a denial of service, or
possibly execute arbitrary code. (CVE-2018-5388)" );
	script_tag( name: "affected", value: "strongswan on Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3771-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3771-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libstrongswan", ver: "5.1.2-0ubuntu2.10", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "strongswan", ver: "5.1.2-0ubuntu2.10", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libstrongswan", ver: "5.6.2-1ubuntu2.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "strongswan", ver: "5.6.2-1ubuntu2.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libstrongswan", ver: "5.3.5-1ubuntu3.7", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "strongswan", ver: "5.3.5-1ubuntu3.7", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

