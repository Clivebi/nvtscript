if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843147" );
	script_version( "2021-09-16T14:01:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 14:01:49 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-29 07:16:15 +0200 (Sat, 29 Apr 2017)" );
	script_cve_id( "CVE-2017-8291", "CVE-2016-10217", "CVE-2016-10219", "CVE-2016-10220", "CVE-2017-5951", "CVE-2017-7207" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for ghostscript USN-3272-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ghostscript'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Ghostscript
improperly handled parameters to the rsdparams and eqproc commands. An attacker
could use these to craft a malicious document that could disable -dSAFER
protections, thereby allowing the execution of arbitrary code, or cause a denial
of service (application crash). (CVE-2017-8291)

Kamil Frankowicz discovered a use-after-free vulnerability in the
color management module of Ghostscript. An attacker could use this
to cause a denial of service (application crash). (CVE-2016-10217)

Kamil Frankowicz discovered a divide-by-zero error in the scan
conversion code in Ghostscript. An attacker could use this to cause
a denial of service (application crash). (CVE-2016-10219)

Kamil Frankowicz discovered multiple NULL pointer dereference errors in
Ghostscript. An attacker could use these to cause a denial of service
(application crash). (CVE-2016-10220, CVE-2017-5951, CVE-2017-7207)" );
	script_tag( name: "affected", value: "ghostscript on Ubuntu 17.04,
  Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3272-1" );
	script_xref( name: "URL", value: "https://www.ubuntu.com/usn/usn-3272-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|12\\.04 LTS|16\\.10|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "ghostscript", ver: "9.10~dfsg-0ubuntu10.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ghostscript-x", ver: "9.10~dfsg-0ubuntu10.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgs9", ver: "9.10~dfsg-0ubuntu10.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgs9-common", ver: "9.10~dfsg-0ubuntu10.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "ghostscript", ver: "9.19~dfsg+1-0ubuntu7.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ghostscript-x", ver: "9.19~dfsg+1-0ubuntu7.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgs9", ver: "9.19~dfsg+1-0ubuntu7.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgs9-common", ver: "9.19~dfsg+1-0ubuntu7.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "ghostscript", ver: "9.05~dfsg-0ubuntu4.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ghostscript-x", ver: "9.05~dfsg-0ubuntu4.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgs9", ver: "9.05~dfsg-0ubuntu4.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgs9-common", ver: "9.05~dfsg-0ubuntu4.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "ghostscript", ver: "9.19~dfsg+1-0ubuntu6.4", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ghostscript-x", ver: "9.19~dfsg+1-0ubuntu6.4", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgs9", ver: "9.19~dfsg+1-0ubuntu6.4", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgs9-common", ver: "9.19~dfsg+1-0ubuntu6.4", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "ghostscript", ver: "9.18~dfsg~0-0ubuntu2.4", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ghostscript-x", ver: "9.18~dfsg~0-0ubuntu2.4", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgs9", ver: "9.18~dfsg~0-0ubuntu2.4", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgs9-common", ver: "9.18~dfsg~0-0ubuntu2.4", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

