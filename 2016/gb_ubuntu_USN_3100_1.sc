if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842914" );
	script_version( "2021-09-20T14:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 14:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-10-13 05:46:44 +0200 (Thu, 13 Oct 2016)" );
	script_cve_id( "CVE-2016-7966" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-27 18:42:00 +0000 (Tue, 27 Dec 2016)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for kdepimlibs USN-3100-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kdepimlibs'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Roland Tapken discovered that the KDE-PIM
  Libraries incorrectly filtered URLs. A remote attacker could use this issue to
 perform an HTML injection attack in the KMail plain text viewer." );
	script_tag( name: "affected", value: "kdepimlibs on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3100-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3100-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libkpimutils4", ver: "4:4.8.5-0ubuntu0.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

