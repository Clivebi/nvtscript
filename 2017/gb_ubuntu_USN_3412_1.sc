if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843300" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-08 07:22:15 +0200 (Fri, 08 Sep 2017)" );
	script_cve_id( "CVE-2017-1000249" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-08 02:29:00 +0000 (Wed, 08 Nov 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for file USN-3412-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'file'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Thomas Jarosch discovered that file
incorrectly handled certain ELF files. An attacker could use this to cause file
to crash, resulting in a denial of service." );
	script_tag( name: "affected", value: "file on Ubuntu 17.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3412-1" );
	script_xref( name: "URL", value: "https://usn.ubuntu.com/usn/usn-3412-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU17\\.04" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "file", ver: "1:5.29-3ubuntu0.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libmagic1:amd64", ver: "1:5.29-3ubuntu0.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libmagic1:i386", ver: "1:5.29-3ubuntu0.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

