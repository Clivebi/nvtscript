if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843380" );
	script_version( "2021-09-10T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 12:01:36 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-28 07:19:15 +0100 (Tue, 28 Nov 2017)" );
	script_cve_id( "CVE-2017-16943" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-04 18:15:00 +0000 (Tue, 04 May 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for exim4 USN-3493-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exim4'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Exim incorrectly
  handled memory in the ESMTP CHUNKING extension. A remote attacker could use this
  issue to cause Exim to crash, resulting in a denial of service, or possibly
  execute arbitrary code. The default compiler options for affected releases
  should reduce the vulnerability to a denial of service." );
	script_tag( name: "affected", value: "exim4 on Ubuntu 17.10,
  Ubuntu 17.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3493-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3493-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(17\\.10|17\\.04)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.89-5ubuntu1.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.89-5ubuntu1.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.88-5ubuntu1.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.88-5ubuntu1.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

