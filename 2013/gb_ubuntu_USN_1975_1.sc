if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841584" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-10-03 10:21:31 +0530 (Thu, 03 Oct 2013)" );
	script_cve_id( "CVE-2013-4254", "CVE-2013-1819" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for linux-ti-omap4 USN-1975-1" );
	script_tag( name: "affected", value: "linux-ti-omap4 on Ubuntu 13.04" );
	script_tag( name: "insight", value: "Vince Weaver discovered a flaw in the perf subsystem of the Linux kernel on
ARM platforms. A local user could exploit this flaw to gain privileges or
cause a denial of service (system crash). (CVE-2013-4254)

A failure to validate block numbers was discovered in the Linux kernel's
implementation of the XFS filesystem. A local user can cause a denial of
service (system crash) if they can mount, or cause to be mounted a
corrupted or special crafted XFS filesystem. (CVE-2013-1819)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "1975-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1975-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-ti-omap4'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU13\\.04" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.5.0-233-omap4", ver: "3.5.0-233.49", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

