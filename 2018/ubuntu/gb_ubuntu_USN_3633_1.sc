if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843507" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-25 08:37:14 +0200 (Wed, 25 Apr 2018)" );
	script_cve_id( "CVE-2017-16995" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-05 20:15:00 +0000 (Tue, 05 Jan 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-euclid USN-3633-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-euclid'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Jann Horn discovered that the Berkeley
  Packet Filter (BPF) implementation in the Linux kernel improperly performed sign
  extension in some situations. A local attacker could use this to cause a denial
  of service (system crash) or possibly execute arbitrary code.
  (CVE-2017-16995)" );
	script_tag( name: "affected", value: "linux-euclid on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3633-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3633-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-9026-euclid", ver: "4.4.0-9026.28", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-euclid", ver: "4.4.0.9026.27", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

