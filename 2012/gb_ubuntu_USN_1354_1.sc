if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1354-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840883" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-03 11:25:29 +0530 (Fri, 03 Feb 2012)" );
	script_cve_id( "CVE-2012-0065" );
	script_xref( name: "USN", value: "1354-1" );
	script_name( "Ubuntu Update for usbmuxd USN-1354-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.04" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1354-1" );
	script_tag( name: "affected", value: "usbmuxd on Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that usbmuxd did not correctly perform bounds checking
  when processing the SerialNumber field of USB devices. An attacker with
  physical access could use this to crash usbmuxd or potentially execute
  arbitrary code as the 'usbmux' user." );
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
	if(( res = isdpkgvuln( pkg: "libusbmuxd1", ver: "1.0.7-1ubuntu0.11.04.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

