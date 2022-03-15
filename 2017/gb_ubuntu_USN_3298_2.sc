if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843179" );
	script_version( "2021-09-17T09:09:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 09:09:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-25 06:50:12 +0200 (Thu, 25 May 2017)" );
	script_cve_id( "CVE-2017-8798" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-30 18:15:00 +0000 (Thu, 30 Apr 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for miniupnpc USN-3298-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'miniupnpc'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3298-1 fixed a vulnerability in
MiniUPnP. This update provides the corresponding update for Ubuntu 17.04.

Original advisory details:

It was discovered that MiniUPnP incorrectly handled memory. A remote
attacker could use this issue to cause a denial of service or possibly
execute arbitrary code with privileges of the user running an application
that uses the MiniUPnP library." );
	script_tag( name: "affected", value: "miniupnpc on Ubuntu 17.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3298-2" );
	script_xref( name: "URL", value: "https://www.ubuntu.com/usn/usn-3298-2" );
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
	if(( res = isdpkgvuln( pkg: "libminiupnpc10", ver: "1.9.20140610-2ubuntu2.17.04.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

