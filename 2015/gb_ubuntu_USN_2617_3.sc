if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842455" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-09-18 10:44:01 +0200 (Fri, 18 Sep 2015)" );
	script_cve_id( "CVE-2015-3202" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for ntfs-3g USN-2617-3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntfs-3g'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-2617-1 fixed a vulnerability in NTFS-3G.
The original patch did not completely address the issue. This update fixes the
problem.

Original advisory details:

Tavis Ormandy discovered that FUSE incorrectly filtered environment
variables. A local attacker could use this issue to gain administrative
privileges." );
	script_tag( name: "affected", value: "ntfs-3g on Ubuntu 15.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2617-3" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2617-3/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU15\\.04" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU15.04"){
	if(( res = isdpkgvuln( pkg: "ntfs-3g", ver: "1:2014.2.15AR.3-1ubuntu0.2", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

