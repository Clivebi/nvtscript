if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1319-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840855" );
	script_version( "2021-08-27T12:01:24+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-01-09 13:29:40 +0530 (Mon, 09 Jan 2012)" );
	script_xref( name: "USN", value: "1319-1" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-29 17:33:00 +0000 (Wed, 29 Jul 2020)" );
	script_cve_id( "CVE-2011-1162", "CVE-2011-2203", "CVE-2011-3353", "CVE-2011-4110" );
	script_name( "Ubuntu Update for linux-ti-omap4 USN-1319-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.04" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1319-1" );
	script_tag( name: "affected", value: "linux-ti-omap4 on Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Peter Huewe discovered an information leak in the handling of reading
  security-related TPM data. A local, unprivileged user could read the
  results of a previous TPM command. (CVE-2011-1162)

  Clement Lecigne discovered a bug in the HFS filesystem. A local attacker
  could exploit this to cause a kernel oops. (CVE-2011-2203)

  Han-Wen Nienhuys reported a flaw in the FUSE kernel module. A local user
  who can mount a FUSE file system could cause a denial of service.
  (CVE-2011-3353)

  A flaw was found in how the Linux kernel handles user-defined key types. An
  unprivileged local user could exploit this to crash the system.
  (CVE-2011-4110)" );
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
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-1209-omap4", ver: "2.6.38-1209.20", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

