if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1578-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841154" );
	script_version( "2019-08-06T11:17:21+0000" );
	script_tag( name: "last_modification", value: "2019-08-06 11:17:21 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "creation_date", value: "2012-09-22 11:59:32 +0530 (Sat, 22 Sep 2012)" );
	script_cve_id( "CVE-2012-3412", "CVE-2012-3430" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_xref( name: "USN", value: "1578-1" );
	script_name( "Ubuntu Update for linux-ti-omap4 USN-1578-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.10" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1578-1" );
	script_tag( name: "affected", value: "linux-ti-omap4 on Ubuntu 11.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Ben Hutchings reported a flaw in the Linux kernel with some network drivers
  that support TSO (TCP segment offload). A local or peer user could exploit
  this flaw to cause a denial of service. (CVE-2012-3412)

  Jay Fenlason and Doug Ledford discovered a bug in the Linux kernel
  implementation of RDS sockets. A local unprivileged user could potentially
  use this flaw to read privileged information from the kernel.
  (CVE-2012-3430)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-1216-omap4", ver: "3.0.0-1216.28", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

